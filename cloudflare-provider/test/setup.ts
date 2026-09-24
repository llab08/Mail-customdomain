// The Worker checks the D1 schema once per isolate (database.js). Tests wipe
// the local database with reset() while the isolate lives on, so every test
// starts with that check forgotten.
import { beforeEach } from 'vitest';
import { forgetSchemaCheck } from '../database.js';

beforeEach(() => {
  forgetSchemaCheck();
});
