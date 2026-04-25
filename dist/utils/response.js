"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Errors = exports.AppError = void 0;
exports.ok = ok;
exports.created = created;
exports.noContent = noContent;
exports.paginate = paginate;
const uuid_1 = require("uuid");
function ok(res, data, meta, status = 200) {
    return res.status(status).json({
        success: true,
        data,
        ...(meta ? { meta } : {}),
        traceId: res.locals.traceId || (0, uuid_1.v4)(),
        timestamp: new Date().toISOString(),
    });
}
function created(res, data) {
    return ok(res, data, undefined, 201);
}
function noContent(res) {
    return res.status(204).send();
}
function paginate(res, data, total, page, limit) {
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
class AppError extends Error {
    message;
    statusCode;
    code;
    details;
    constructor(message, statusCode = 400, code = 'BAD_REQUEST', details) {
        super(message);
        this.message = message;
        this.statusCode = statusCode;
        this.code = code;
        this.details = details;
        this.name = 'AppError';
    }
}
exports.AppError = AppError;
exports.Errors = {
    notFound: (resource) => new AppError(`${resource} not found`, 404, 'NOT_FOUND'),
    unauthorized: (msg = 'Unauthorized') => new AppError(msg, 401, 'UNAUTHORIZED'),
    forbidden: (msg = 'Forbidden') => new AppError(msg, 403, 'FORBIDDEN'),
    validation: (msg, details) => new AppError(msg, 422, 'VALIDATION_ERROR', details),
    conflict: (msg) => new AppError(msg, 409, 'CONFLICT'),
    rateLimit: () => new AppError('Too many requests', 429, 'RATE_LIMIT_EXCEEDED'),
};
