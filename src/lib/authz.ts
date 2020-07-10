import { NowRequest, NowResponse } from '@vercel/node/dist';
import { ForbiddenError } from './errors';

export interface NowJwtAuthzOptions {
  customScopeKey?: string;
  checkAllScopes?: boolean;
}
export interface NowJwtAuthzRequestHandler {
  (req: NowRequest, res: NowResponse, user?: Record<string, any>): Promise<
    void
  >;
}

export const getScopesFromUser = (
  user: Record<string, any>,
  scopeKey: string
): string[] | undefined => {
  if (typeof user[scopeKey] === 'string') {
    return user[scopeKey].split(' ');
  } else if (Array.isArray(user[scopeKey])) {
    return user[scopeKey];
  }
  return;
};

/**
 * Build function to verify required scope(s) in decoded user token
 * @param expectedScopes
 * @param options
 * @return authorization function for requests
 */
export default (
  expectedScopes: string[],
  options?: NowJwtAuthzOptions
): NowJwtAuthzRequestHandler => {
  if (!Array.isArray(expectedScopes)) {
    throw new Error(
      'Parameter expectedScopes must be an array of strings representing the scopes for the endpoint(s)'
    );
  }

  return async (
    _req: NowRequest,
    _res: NowResponse,
    user?: Record<string, any>
  ): Promise<void> => {
    if (expectedScopes.length === 0) {
      return;
    }

    const scopeKey = (options && options.customScopeKey) || 'scope';

    if (!user) {
      throw new ForbiddenError('User token missing', expectedScopes);
    }

    const userScopes = getScopesFromUser(user, scopeKey);
    if (!userScopes) {
      throw new ForbiddenError('Insufficient scope', expectedScopes);
    }

    const allowed =
      options && options.checkAllScopes
        ? expectedScopes.every(scope => userScopes.includes(scope))
        : expectedScopes.some(scope => userScopes.includes(scope));

    if (!allowed) {
      throw new ForbiddenError('Insufficient scope', expectedScopes);
    }
  };
};
