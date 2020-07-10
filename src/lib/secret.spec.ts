import test from 'ava';
import { default as nowJwtSecret, NowJwtSecretOptions } from './secret';

test('default should return secret provider', t => {
  const options: NowJwtSecretOptions = {
    jwksUri: 'http://localhost/.well-known/jwks.json'
  };
  const handler = nowJwtSecret(options);
  t.is(typeof handler, 'function');
});
