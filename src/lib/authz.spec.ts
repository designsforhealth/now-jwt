import test from 'ava';
import { default as nowJwtAuthz, NowJwtAuthzOptions } from './authz';

test('default should return request handler', t => {
  const expectedScopes = ['read:current_user'];
  const options: NowJwtAuthzOptions = {};
  const handler = nowJwtAuthz(expectedScopes, options);
  t.is(typeof handler, 'function');
});
