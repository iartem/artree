export enum ErrCode {
  INCONSISTENT_STATE = 'INCONSISTENT_STATE',
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  ENCODING_ERROR = 'ENCODING_ERROR',
  INVALID_ARGUMENT = 'INVALID_ARGUMENT',
}

const messages: { [k in ErrCode]: string } = {
  [ErrCode.INCONSISTENT_STATE]: 'Inconsistent ART state',
  [ErrCode.INVALID_SIGNATURE]: 'Invalid data signature',
  [ErrCode.ENCODING_ERROR]: 'Data encoding error',
  [ErrCode.INVALID_ARGUMENT]: 'Invalid argument error',
};

/**
 * Error class, used throughout the project
 */
export class Err extends Error {
  constructor(public readonly code: ErrCode, details?: string) {
    super(messages[code] + (details ? ': ' + details : ''));
  }
}
