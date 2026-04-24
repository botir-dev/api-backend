import { Request, Response } from 'express';
import { v4 as uuid } from 'uuid';

export function ok(res: Response, data: any, meta?: any, status = 200) {
  return res.status(status).json({
    success: true,
    data,
    ...(meta ? { meta } : {}),
    traceId: (res.locals.traceId as string) || uuid(),
    timestamp: new Date().toISOString(),
  });
}

export function created(res: Response, data: any) {
  return ok(res, data, undefined, 201);
}

export function noContent(res: Response) {
  return res.status(204).send();
}

export function paginate(
  res: Response,
  data: any[],
  total: number,
  page: number,
  limit: number
) {
  const totalPages = Math.ceil(total / limit);
  return ok(res, data, {
    total,
    page,
    limit,
    totalPages,
    hasNext: page < totalPages,
    hasPrev: page > 1,
  });
}

export class AppError extends Error {
  constructor(
    public message: string,
    public statusCode: number = 400,
    public code: string = 'BAD_REQUEST',
    public details?: any
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export const Errors = {
  notFound: (resource: string) => new AppError(`${resource} not found`, 404, 'NOT_FOUND'),
  unauthorized: (msg = 'Unauthorized') => new AppError(msg, 401, 'UNAUTHORIZED'),
  forbidden: (msg = 'Forbidden') => new AppError(msg, 403, 'FORBIDDEN'),
  validation: (msg: string, details?: any) => new AppError(msg, 422, 'VALIDATION_ERROR', details),
  conflict: (msg: string) => new AppError(msg, 409, 'CONFLICT'),
  rateLimit: () => new AppError('Too many requests', 429, 'RATE_LIMIT_EXCEEDED'),
};
