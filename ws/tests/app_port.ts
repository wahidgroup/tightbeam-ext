import { ENVIRONMENT } from "./env.js";

/**
 * The port of the e2e app, which the stack allocates and which the dev server
 * binds and the Playwright lane opens.
 */
export const APP_PORT = ENVIRONMENT.count("E2E_APP_HOST_PORT");
