//! Server reflection on a coupled edge: the descriptors of the methods that
//! it routes alone, for a caller that it identifies.
//!
//! # Sources
//!
//! - gRPC Server Reflection, `grpc/grpc` `doc/server-reflection.md`:
//!   <https://github.com/grpc/grpc/blob/master/doc/server-reflection.md>

use core::convert::Infallible;
use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use http::{Request as HttpRequest, Response as HttpResponse};
use prost::Message;
use prost_types::{FileDescriptorProto, FileDescriptorSet};
use tonic::body::Body;
use tonic_reflection::server::Builder;
use tower_service::Service;

use super::error::CoupleError;
use super::method::MethodPath;
use crate::service::{ReflectionVersion, Versions};
use crate::tunnel::BoxFuture;

/// One version of the reflection service, as a call.
pub(crate) type Serve = Arc<dyn Fn(HttpRequest<Body>) -> BoxFuture<HttpResponse<Body>> + Send + Sync>;

/// The reflection service of a coupled edge, in both versions.
#[derive(Clone)]
pub(crate) struct Reflection {
	versions: Versions<Serve>,
}

impl Reflection {
	/// The reflection of `methods`, the routed methods of the edge, from
	/// `descriptors`, an encoded `FileDescriptorSet`, pruned to them.
	///
	/// # Errors
	///
	/// - [`CoupleError::Reflection`] -- `descriptors` do not decode, or a descriptor does not resolve.
	pub(crate) fn new<'a>(
		descriptors: &[u8],
		methods: impl IntoIterator<Item = &'a MethodPath>,
	) -> Result<Self, CoupleError> {
		let routed = RoutedSurface::of(methods);
		let decoded = FileDescriptorSet::decode(descriptors).map_err(|error| CoupleError::Reflection(error.into()))?;
		let pruned = routed.prune(decoded);
		let services = routed.services();

		let builder = || {
			let builder = Builder::configure().register_file_descriptor_set(pruned.clone());
			services
				.iter()
				.fold(builder, |builder, service| builder.with_service_name(service.clone()))
		};

		let v1 = builder().build_v1().map_err(|error| CoupleError::Reflection(error.into()))?;
		let v1alpha = builder()
			.build_v1alpha()
			.map_err(|error| CoupleError::Reflection(error.into()))?;
		let versions = Versions { v1: Self::serve(v1), v1alpha: Self::serve(v1alpha) };
		Ok(Self { versions })
	}

	/// The call of one version of the service.
	fn serve<S>(server: S) -> Serve
	where
		S: Service<HttpRequest<Body>, Response = HttpResponse<Body>, Error = Infallible>
			+ Clone
			+ Send
			+ Sync
			+ 'static,
		S::Future: Send + 'static,
	{
		Arc::new(move |request| {
			let mut server = server.clone();
			Box::pin(async move {
				match server.call(request).await {
					Ok(response) => response,
					Err(never) => match never {},
				}
			})
		})
	}

	/// The service of `version`.
	pub(crate) fn of(&self, version: ReflectionVersion) -> Serve {
		Arc::clone(version.of(&self.versions))
	}
}

/// The routed methods of an edge, by the full name of their service.
struct RoutedSurface {
	methods: BTreeMap<String, BTreeSet<String>>,
}

impl RoutedSurface {
	/// The surface of `methods`.
	fn of<'a>(methods: impl IntoIterator<Item = &'a MethodPath>) -> Self {
		let mut surface: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
		for method in methods {
			let service = surface.entry(method.service().to_owned()).or_default();
			service.insert(method.name().to_owned());
		}

		Self { methods: surface }
	}

	/// The full names of the routed services, in order.
	fn services(&self) -> Vec<String> {
		self.methods.keys().cloned().collect()
	}

	/// `set` with the routed services and methods alone, in the files that
	/// define them and the files those depend on.
	fn prune(&self, set: FileDescriptorSet) -> FileDescriptorSet {
		let mut files: Vec<FileDescriptorProto> = set.file.into_iter().map(|file| self.routed_in(file)).collect();
		let mut kept: BTreeSet<String> = files
			.iter()
			.filter(|file| !file.service.is_empty())
			.map(|file| file.name().to_owned())
			.collect();

		let mut pending: Vec<String> = kept.iter().cloned().collect();
		while let Some(name) = pending.pop() {
			let file = files.iter().find(|file| file.name() == name);
			for dependency in file.into_iter().flat_map(|file| file.dependency.iter()) {
				if kept.insert(dependency.clone()) {
					pending.push(dependency.clone());
				}
			}
		}

		files.retain(|file| kept.contains(file.name()));
		FileDescriptorSet { file: files }
	}

	/// `file` with the routed services and methods alone.
	fn routed_in(&self, mut file: FileDescriptorProto) -> FileDescriptorProto {
		let package = file.package().to_owned();
		file.service.retain_mut(|service| {
			let name = match package.as_str() {
				"" => service.name().to_owned(),
				package => format!("{package}.{}", service.name()),
			};
			let Some(routed) = self.methods.get(&name) else {
				return false;
			};

			service.method.retain(|method| routed.contains(method.name()));
			!service.method.is_empty()
		});
		file
	}
}

impl fmt::Debug for Reflection {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Reflection").finish_non_exhaustive()
	}
}
