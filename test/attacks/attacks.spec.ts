import { messageSignatures } from './message-signatures';

describe('Attacks', () => {
  beforeEach(() => {
    global.console = require('console');
  });

  messageSignatures();
});
