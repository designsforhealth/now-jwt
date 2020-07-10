import test from 'ava';
import { default as nowJwt, getTokenFromHeaders, NowJwtOptions } from './jwt';
import * as sinon from 'ts-sinon';
import { NowRequest } from '@vercel/node/dist';
import { UnauthorizedError } from './errors';

test('getTokenFromHeaders() should return undefined with empty header', t => {
  const req = sinon.stubInterface<NowRequest>();
  const result = getTokenFromHeaders(req, true);
  t.is(result, undefined);
});

test('getTokenFromHeaders() should throw bad format error', t => {
  const req = sinon.stubInterface<NowRequest>();
  req.headers.authorization = 'Bearer_bad';
  const shouldThrow = () => getTokenFromHeaders(req, true);
  t.throws(shouldThrow, {
    instanceOf: UnauthorizedError,
    code: 'credentials_bad_format'
  });
});

test('getTokenFromHeaders() should throw bad scheme error when required', t => {
  const req = sinon.stubInterface<NowRequest>();
  req.headers.authorization = 'BadScheme token';
  const shouldThrow = () => getTokenFromHeaders(req, true);
  t.throws(shouldThrow, {
    instanceOf: UnauthorizedError,
    code: 'credentials_bad_scheme'
  });
});

test('getTokenFromHeaders() should return undefined when bad scheme and not required', t => {
  const req = sinon.stubInterface<NowRequest>();
  req.headers.authorization = 'BadScheme token';
  const result = getTokenFromHeaders(req, false);
  t.is(result, undefined);
});

test('getTokenFromHeaders() should return token', t => {
  const req = sinon.stubInterface<NowRequest>();
  req.headers.authorization = 'Bearer token';
  const result = getTokenFromHeaders(req, true);
  t.is(result, 'token');
});

test('default should return request handler', t => {
  const options: NowJwtOptions = {
    secret: 'static_secret',
    algorithms: ['RS256']
  };
  const result = nowJwt(options);
  t.is(typeof result, 'function');
});
