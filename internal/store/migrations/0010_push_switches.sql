-- M9.1 push switches (D94): a device may ask for call pushes only. A withdrawn device keeps its row with token ''.
ALTER TABLE push_tokens ADD COLUMN messages_off INTEGER NOT NULL DEFAULT 0;
