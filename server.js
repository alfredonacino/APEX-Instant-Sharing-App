/**
 * Process entry point: starts the HTTP/HTTPS listeners.
 *
 * The app factory (src/app.js) and the listener wiring (src/runtime.js) are
 * separate modules so tests can use either without a real socket. This file
 * always listens - no "am I the main module?" check, because process managers
 * such as pm2 launch ESM through a wrapper, which makes process.argv[1] point
 * at the wrapper rather than at this file.
 */
import { start, attachProcessHandlers } from './src/runtime.js';

const runtime = await start();
attachProcessHandlers(runtime);
