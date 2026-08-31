import multer from 'multer';
import { config } from '../config.js';

export function notFoundHandler(req, res) {
  res.status(404).json({ error: 'Endpoint not found', code: 'not_found' });
}

/* eslint-disable-next-line no-unused-vars -- Express identifies error handlers by arity */
export function errorHandler(error, req, res, next) {
  if (error instanceof multer.MulterError) {
    const status = error.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    const message =
      error.code === 'LIMIT_FILE_SIZE'
        ? `File is larger than the ${Math.round(config.maxUploadBytes / 1024 / 1024)} MB limit`
        : error.code === 'LIMIT_FILE_COUNT'
          ? `At most ${config.maxFilesPerUpload} files per upload`
          : `Upload rejected: ${error.message}`;
    return res.status(status).json({ error: message, code: error.code });
  }

  const status = Number(error.status || error.statusCode || 500);
  if (status >= 500) {
    console.error('[error]', req.method, req.originalUrl, error);
  }

  return res.status(status).json({
    error: status >= 500 || !error.expose ? 'Something went wrong' : error.message,
    code: error.code ?? (status >= 500 ? 'internal' : 'error'),
    ...(error.details ? { details: error.details } : {}),
  });
}
