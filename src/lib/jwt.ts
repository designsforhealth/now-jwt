import * as jwt from 'jsonwebtoken';
import { UnauthorizedError } from './errors';
import { NowRequest, NowResponse } from '@vercel/node/dist';
import { promisify } from 'util';

type AsyncVerifyFunction = (
  token: string,
  secretOrPublicKey: jwt.Secret | jwt.GetPublicKeyOrSecret,
  options?: jwt.VerifyOptions,
  callback?: jwt.VerifyCallback
) => void;

const jwtVerify = promisify(jwt.verify as AsyncVerifyFunction);

const DEFAULT_REVOKED_FUNCTION = async () => false;

export type Secret = string | Buffer;

export interface SecretCallbackLong {
  (req: NowRequest, header: any, payload: any): Promise<Secret>;
}
export interface SecretCallback {
  (req: NowRequest, payload: any): Promise<Secret>;
}
export interface IsRevokedCallback {
  (req: NowRequest, payload: any): Promise<boolean>;
}
export interface NowJwtOptions extends jwt.VerifyOptions {
  secret: Secret | SecretCallback | SecretCallbackLong;
  credentialsRequired?: boolean;
  isRevoked?: IsRevokedCallback;
}
export interface NowJwtRequestHandler {
  (req: NowRequest, res: NowResponse): Promise<Record<string, any> | undefined>;
}

const wrapStaticSecretInCallback = (
  secret: Secret
): SecretCallback => async () => secret;

export const getTokenFromHeaders = (
  req: NowRequest,
  credentialsRequired: boolean
): string | undefined => {
  if (req.headers && req.headers.authorization) {
    const parts = req.headers.authorization.split(' ');
    if (parts.length !== 2) {
      /*
      throw new UnauthorizedError('credentials_bad_format', {
        message: 'Format is Authorization: Bearer [token]'
      });
       */
    }

    const [scheme, credentials] = parts;
    if (/^Bearer$/i.test(scheme)) {
      return credentials;
    } else {
      if (credentialsRequired) {
        throw new UnauthorizedError('credentials_bad_scheme', {
          message: 'Format is Authorization: Bearer [token]'
        });
      }
    }
  }
  return;
};

export const decodeToken = (token: string): Record<string, any> => {
  let result;
  try {
    result = jwt.decode(token, { complete: true }) || {};
  } catch (err) {
    throw new UnauthorizedError('invalid_token', err);
  }
  if (typeof result !== 'object') {
    throw new UnauthorizedError('invalid_token', {
      message: 'decoded token must be an object'
    });
  }
  return result;
};

/**
 * Build function to authenticate request using JWT token in request
 * @param options
 * @return authentication function for requests
 */
export default (options: NowJwtOptions): NowJwtRequestHandler => {
  if (!options || !options.secret) throw new Error('secret should be set');

  if (!options.algorithms) throw new Error('algorithms should be set');
  if (!Array.isArray(options.algorithms))
    throw new Error('algorithms must be an array');

  const secretCallback =
    typeof options.secret === 'function'
      ? options.secret
      : wrapStaticSecretInCallback(options.secret);

  const isRevokedCallback = options.isRevoked || DEFAULT_REVOKED_FUNCTION;

  const credentialsRequired =
    typeof options.credentialsRequired === 'undefined'
      ? true
      : options.credentialsRequired;

  return async (
    req: NowRequest,
    _res: NowResponse
  ): Promise<Record<string, any> | undefined> => {
    if (
      req.method === 'OPTIONS' &&
      req.headers['access-control-request-headers']
    ) {
      const hasAuthInAccessControl = !!~req.headers[
        'access-control-request-headers'
      ]
        .split(',')
        .map(header => header.trim())
        .indexOf('authorization');

      if (hasAuthInAccessControl) {
        return;
      }
    }

    const token = getTokenFromHeaders(req, credentialsRequired);

    if (!token) {
      if (credentialsRequired) {
        throw new UnauthorizedError('credentials_required', {
          message: 'No authorization token was found'
        });
      } else {
        return;
      }
    }

    const decodedToken = decodeToken(token);

    const getSecret = (): Promise<Secret> => {
      const arity = secretCallback.length;
      if (arity === 3) {
        return (secretCallback as SecretCallbackLong)(
          req,
          decodedToken.header,
          decodedToken.payload
        );
      }
      return (secretCallback as SecretCallback)(req, decodedToken.payload);
    };

    const verifyToken = (secret: Secret): Promise<any> =>
      jwtVerify(token, secret, options).catch((err: Error) => {
        console.error('Token validation failed', err);
        throw new UnauthorizedError('invalid_token', err);
      });

    const checkRevoked = (
      decoded: Record<string, any>
    ): Promise<Record<string, any>> =>
      isRevokedCallback(req, decodedToken.payload).then(revoked => {
        if (revoked) {
          throw new UnauthorizedError('revoked_token', {
            message: 'The token has been revoked.'
          });
        }
        return decoded;
      });

    return getSecret()
      .then(verifyToken)
      .then(checkRevoked);
  };
};
