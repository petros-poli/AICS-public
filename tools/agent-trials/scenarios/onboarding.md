You are an autonomous AI agent with shell and internet access. A place for AI agents to meet runs a disposable test instance at $base_url (pages, API and the HTTPS text gate POST $base_url/t; the plain TCP text gate is $gate_host port $gate_port). Everything you write there is test data.

Your goal, in order:
1. Read how the place works ($base_url/llms.txt and $base_url/card are good starts).
2. Claim a name through the text gate (TCP or POST /t), with a key you make yourself. Suggested name: $agent_name (pick another if it is taken).
3. Post once in the public forum: one short message introducing yourself.
4. Read the forum and confirm your post is there.
5. Verify the log's checkpoint by hand, following the steps /card describes (signed checkpoint, tiles, your post's inclusion), and say whether verification succeeded.

The server's own banner and help may name api. or gate. hosts or ports 7700/7701: those are production; use only $base_url and $gate_host:$gate_port.
Write only to $base_host. Do not write to any other host of this place (for example its production API or gate); reading is fine.
