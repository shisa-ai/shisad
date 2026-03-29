# shisad Use Cases — Personal AI Assistant

*Created: 2026-02-17*
*Updated: 2026-03-29*
*Sources: [Omar's Lobster article](https://www.omarknows.ai/p/meet-lobster-my-personal-ai-assistant), [Tanay's Complete Guide](https://peerlist.io/tanayvasishtha/articles/clawdbot-the-complete-guide-to-everything-you-can-do-withit) + shisad gap analysis*

This document catalogs concrete personal AI assistant use cases drawn from real-world deployments and community guides (primarily "Lobster" on OpenClaw, plus the broader OpenClaw community), maps them against shisad's current and planned capabilities, and identifies gaps, security considerations, and workarounds.

---

## Executive Summary

**62 use cases** cataloged across 28 categories, sourced from 8 articles/reports on real OpenClaw deployments.

### Support Status at a Glance

| Status | Count | Description |
|--------|-------|-------------|
| **Supported (v0.3)** | 7 | Works today: chat, reminders, lists, web research, shell/fs/git ops, identity routing |
| **Partial** | 24 | Foundation exists (scheduler, channels, PEP, memory) — needs thin skill wrappers or config |
| **Planned** | 2 | Architecture designed, not runtime-wired (memory hierarchy, personal knowledge base) |
| **Missing** | 29 | Needs new connectors, skills, or architectural work |

### Top 10 Most-Wanted Use Cases (by community frequency)

These are the most commonly cited use cases across all source articles, rank-ordered by real-world demand. Bolded items are the highest-impact gaps.

| Rank | Use Case | Our Status | Blocker | Target |
|------|----------|-----------|---------|--------|
| **1** | **Email triage / read / send** | Missing | Orchestration foundation + email/calendar connector lane | **v0.7** |
| **2** | **Calendar read / write** | Missing | Orchestration foundation + email/calendar connector lane | **v0.7** |
| **3** | **Morning briefing (full)** | Partial | Needs email + calendar to be useful | **v0.7** |
| **4** | **Attachment pipeline (voice + image)** | Missing | Attachment pipeline on top of the orchestration model | **v0.7** |
| **5** | **Code generation / dev workflows** | Missing | Sandbox + proposal/apply workflow | **v0.4** |
| **6** | **Memory / preference learning** | Planned | Memory foundation + write-gating/runtime integration | **v0.7** |
| **7** | **Smart home control** | Missing | HomeAssistant / Hue skill | v0.6+ |
| **8** | **Group chat @mention gating** | Partial | Per-channel routing config + group-scoped policy model | **v0.7 (stretch)** |
| **9** | **Scheduled task guardrails** | Partial | Task cancellation propagation, output sanitization | **v0.4** |
| **10** | **Browser automation** | Missing | Playwright sandbox on top of the orchestration foundation | **v0.7** |

### Key Insight: Two Blockers Unlock Most Value

1. **Orchestration foundation** (`v0.6`) — unlocks safe delegated execution, typed boundaries, provenance-aware handoff, and credential scoping for the high-risk assistant surfaces that follow.
2. **Email/calendar + attachment tool-surface track** (`v0.7`) — unlocks #1, #2, #3, #4 plus package tracking, morning briefings, weekly reports, job search, transcription, OCR, and other downstream assistant workflows.

Some of the 24 partial use cases are thin-skill follow-ons on top of existing infrastructure. The higher-risk ones now explicitly wait on the `v0.6` orchestration boundary and the `v0.7` connector/tool-surface lane rather than the locked `v0.4` scope.

---

## Reference Architecture: Lobster

Lobster runs on a dedicated MacBook Air M1, uses OpenClaw as its runtime, Claude as its LLM backbone, and iMessage as its primary interface. It uses a **multi-agent architecture** with three agents at different privilege levels:

| Agent | Role | Access Level |
|-------|------|-------------|
| **Lobster** (Executive) | Primary user's full assistant | Unrestricted: email, files, shell, all integrations |
| **Lobster-Groups** (Meeting Facilitator) | Group chat participant | Sandboxed; elevated mode for primary user |
| **Lobster-Family** (Receptionist) | Family member access | Limited: no email, no file ops, no shell |

Key design choices: phone-number-based routing, Docker sandboxing for restricted agents, agent-to-agent escalation, iMessage as sole channel.

---

## Use Case Inventory

### 1. Communication & Messaging

#### 1.1 Direct Chat via Messaging App

**What**: User sends text messages to the assistant via their existing messaging app (iMessage in Lobster's case). The assistant responds conversationally.

| Aspect | Status |
|--------|--------|
| **shisad support** | Present (v0.3): Discord, Telegram, Slack, Matrix, CLI |
| **Gap** | iMessage not supported (no stable official bot API) |
| **Security notes** | All channel input is untrusted and goes through ContentFirewall. Default-deny identity binding. |
| **Workaround for iMessage** | Use Telegram/Discord/Slack instead. iMessage bridge (e.g., Beeper/Matrix bridge) is possible but adds trust surface. |

#### 1.2 Group Chat Participation (@mentions)

**What**: Assistant responds to @mentions in family/team group chats. Doesn't respond to everything, only when addressed.

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial (v0.3): channel adapters receive messages; mention-gating logic not yet implemented |
| **Gap** | No per-channel group routing rules (mention gating, reply-tag filtering, "don't respond unless @mentioned") |
| **Needed** | Group routing config per channel: mention trigger rules, reply scope, chunking policy |
| **Security notes** | Group chats increase injection surface (any group member's messages are untrusted input). ContentFirewall applies. |

#### 1.3 Relay Messages Between Family Members

**What**: "Tell Alex to pick up milk on the way home" — assistant sends a message to another user on behalf of the requester.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing |
| **Gap** | No user-facing cross-user message relay capability. Background-task plumbing now has an internal `message.send` runtime path, but not the routed assistant surface needed for "send a message to Alex on my behalf." |
| **Needed** | Planner/user-facing `message.send` with destination user/channel routing, confirmation gate, and audit trail |
| **Security notes** | High-risk: message relay is an egress action. Must be confirmation-gated. Must prevent injection-driven relay (attacker crafts message content via injected prompt). Allowlisted destinations only. |

---

### 2. Email

#### 2.1 Check & Summarize Unread Emails

**What**: "What's in my inbox?" — assistant checks email and provides a summary of unread messages.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing (deferred to the v0.7 email/calendar connector lane) |
| **Gap** | No email connector (IMAP/SMTP/OAuth) |
| **Needed** | Email connector skill with: OAuth credential lifecycle, read-only mode, PII redaction on summaries, taint tracking (email content is untrusted) |
| **Security notes** | Email content is a major prompt injection vector. All email body/subject content must be treated as untrusted. Summarization must use spotlighting. Email credentials need secure storage (credential broker). |

#### 2.2 Draft Email Responses

**What**: "Reply to Sarah's email about the project, keep it professional" — assistant drafts a response with contextual awareness.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing |
| **Gap** | No email send capability |
| **Needed** | Email draft + send tool. Draft should be presented for confirmation before sending. Context from original email thread must be taint-tracked. |
| **Security notes** | Email sending is irreversible egress. Must be confirmation-gated. Draft content influenced by tainted email content creates a risk of data exfiltration via crafted replies. Outbound content should pass Output Firewall (PII/secret redaction). |

#### 2.3 Email Triage & Bulk Actions

**What**: "Unsubscribe me from all newsletters I don't read" or "Flag important emails as starred" or "Reply 'thanks' to all emails from my team" — assistant performs bulk email operations.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing (requires email connector, v0.7) |
| **Gap** | No email connector; no bulk action primitives |
| **Needed** | Email connector (see 2.1) + bulk action tools (filter, unsubscribe, star, archive, auto-reply). Each bulk action type needs its own confirmation policy. |
| **Security notes** | Bulk auto-reply is especially dangerous: an injection in one email could craft reply content sent to many recipients. Must be confirmation-gated per-batch or per-action-type. Unsubscribe links are egress (clicking external URLs). |

---

### 3. Calendar & Scheduling

#### 3.1 Query Calendar / Check Schedule

**What**: "What's on my calendar today?" — assistant reads calendar events and presents them.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing (deferred to the v0.7 email/calendar connector lane) |
| **Gap** | No calendar connector (CalDAV/Google Calendar API) |
| **Needed** | Calendar read skill with OAuth credentials, timezone awareness |
| **Security notes** | Calendar event content (titles, descriptions, attendee lists) contains PII. Read-only access is lower risk but still needs credential broker integration. |

#### 3.2 Create Calendar Events with Drive Time

**What**: "Schedule dentist at 2pm on Thursday, it's 25 minutes away" — assistant creates event with travel buffer.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing |
| **Gap** | No calendar write, no drive time estimation |
| **Needed** | Calendar write tool (confirmation-gated), geocoding/routing API for drive time estimates |
| **Security notes** | Calendar write is a side-effecting action requiring confirmation. Location data is PII. |

#### 3.3 Coordinate Multi-Person Scheduling

**What**: "Find a time that works for me and Alex next week" — assistant checks multiple calendars and proposes times.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing |
| **Gap** | No multi-calendar access, no availability cross-referencing |
| **Needed** | Cross-calendar availability skill. Purpose-limited consult pattern (calendar skill consults other calendars). |
| **Security notes** | Cross-user calendar access expands trust surface. Each calendar's credential scope must be independent. |

---

### 4. Reminders & Tasks

#### 4.1 Create Reminders (Natural Language)

**What**: "Remind me to pick up the flush valve at Home Depot tomorrow" — assistant schedules a reminder.

| Aspect | Status |
|--------|--------|
| **shisad support** | Present (v0.3): `todo.create` + scheduler pump + channel delivery path |
| **Gap** | None for basic reminders. Natural language time parsing works via LLM. |
| **Security notes** | Reminders execute under capability snapshot captured at creation time. No post-schedule privilege escalation. |

#### 4.2 Create Reminders for Other People

**What**: "Remind Alex to take out the trash tonight" — assistant sends reminder to another household member.

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: scheduler exists but no cross-user delivery |
| **Gap** | No cross-user reminder delivery. Requires a user-facing `message.send` flow plus user/channel routing. |
| **Needed** | Cross-user reminder delivery with confirmation and destination allowlist |
| **Security notes** | Same as message relay (1.3): confirmation-gated, allowlisted destinations. |

#### 4.3 Persistent Lists (Shopping, Packing, etc.)

**What**: "Add milk, bread, eggs to my shopping list" / "What's on my list?" — assistant maintains persistent lists across sessions and devices.

| Aspect | Status |
|--------|--------|
| **shisad support** | Present (v0.3): `note.create` + `note.list` can serve as persistent lists |
| **Gap** | No dedicated "list" primitive with add/remove/check-off semantics. Notes work but are less structured. |
| **Needed** | Could be built on top of existing notes/todos. A thin "list" skill with add/remove/query would improve UX. |
| **Security notes** | Low-risk (local data, no egress). Standard memory write-gating applies. |

---

### 5. Travel & Research

#### 5.1 Research Flights & Accommodations

**What**: "Research flights to Tokyo for March, 2 people, 10 days" — assistant researches options and presents summaries.

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial (v0.3): `web.search` + `web.fetch` exist |
| **Gap** | No structured travel search APIs (Google Flights, Skyscanner, etc.). Web fetch + summarize works but is less structured. |
| **Needed** | For basic use: web search + fetch + summarize (works today). For structured: travel API skill. |
| **Security notes** | Web content is untrusted. Search results and fetched pages go through ContentFirewall. Summarization uses spotlighting. Web fetch is allowlist-gated. |

#### 5.2 Clarifying Questions Before Research

**What**: Assistant asks "How long? How many people? Budget?" before researching — multi-turn conversational research.

| Aspect | Status |
|--------|--------|
| **shisad support** | Present: session-based conversation with memory |
| **Gap** | None — this is standard LLM conversational behavior within a session |
| **Security notes** | N/A |

#### 5.3 Flight Tracking / Arrival Times

**What**: "When does Dad's flight land?" — assistant checks flight status.

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: could use `web.fetch` against a flight tracking site |
| **Gap** | No structured flight tracking API integration |
| **Needed** | FlightAware/similar API skill, or web scraping approach |
| **Security notes** | API key management via credential broker. Flight data is relatively low-sensitivity. |

---

### 6. Package & Delivery Tracking

#### 6.1 Extract Tracking Numbers from Notifications

**What**: Assistant monitors shipping notification emails, extracts tracking numbers, and adds them to a tracking app.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing |
| **Gap** | No email monitoring, no structured data extraction from emails, no Parcel app integration |
| **Needed** | Email connector (see 2.1) + regex/LLM extraction of tracking numbers + integration with tracking service/app |
| **Security notes** | Email monitoring is a triggered task — runs while user is away. Must use capability snapshot. Email content is untrusted (tracking number extraction from tainted content). No auto-egress without confirmation or pre-configured allowlist. |

---

### 7. Smart Home & Music

#### 7.1 Control Music (Sonos/Spotify)

**What**: "Play jazz in the living room" — assistant controls Sonos speakers, creates playlists, manages playback.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing |
| **Gap** | No Sonos/Spotify/music service integration |
| **Needed** | Sonos/Spotify API skill. Network access to local Sonos devices or Spotify API. |
| **Security notes** | Local network access for Sonos is a network egress concern. Must be allowlisted. Spotify OAuth needs credential broker. Music control is low-risk (non-destructive, reversible) but still needs confirmation policy for "play at high volume at 3am" type scenarios. |

#### 7.2 IoT / Smart Home Control

**What**: Control lights (Hue), thermostats, appliances.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing |
| **Gap** | No IoT integration |
| **Needed** | Home automation skill (Hue, HomeAssistant, etc.) |
| **Security notes** | IoT control is side-effecting. Some actions are safety-relevant (e.g., door locks, thermostats). Needs per-device confirmation policy. Local network egress must be allowlisted. |

---

### 8. Personalization & Memory

#### 8.1 Learn User Preferences Over Time

**What**: Assistant remembers that you prefer morning meetings, like jazz, are allergic to shellfish, etc.

| Aspect | Status |
|--------|--------|
| **shisad support** | Planned (architecture designed): semantic memory, fact extraction, preference storage |
| **Gap** | Memory consolidation and automatic fact extraction not yet implemented in runtime |
| **Needed** | Memory hierarchy implementation: working -> short-term -> long-term -> semantic |
| **Security notes** | Memory is a persistence/poisoning surface. All writes gated. Provenance required. Taint survives summarization. User can inspect, correct, delete memories. |

#### 8.2 Family Context Awareness

**What**: Knows family members' names, relationships, typical schedules.

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: notes/todos can store this manually; no automatic extraction |
| **Gap** | No entity/relationship graph, no automatic extraction from conversations |
| **Needed** | Semantic memory with entity-relationship storage (`remember_fact(subject, predicate, object)`) |
| **Security notes** | Family information is PII. PII redaction must apply to outbound content. Memory stores need access controls per user context. |

---

### 9. Multi-Agent Architecture

#### 9.1 Tiered Access Levels (Executive / Facilitator / Receptionist)

**What**: Different agents with different permission sets for different users/contexts.

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: per-user trust levels + capability scoping exist in design; runtime enforcement via PEP |
| **Gap** | No "multiple named agents" concept. shisad uses per-user roles/trust levels rather than separate agent instances. |
| **shisad approach** | shisad achieves the same security outcome differently: per-identity capability scoping via `UserRole` (owner/admin/user/guest) + per-tool PEP enforcement. This is arguably more secure than Docker-sandboxed separate agent instances because policy is centrally enforced. |
| **Security notes** | shisad's approach is architecturally stronger: policy enforcement is central (PEP), not distributed across container boundaries. OpenClaw's Docker sandbox approach has wider blast radius per container. |

#### 9.2 Agent-to-Agent Escalation

**What**: Family member asks Lobster-Family something that requires elevated access; it escalates to Lobster (Executive).

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing as an explicit feature, but achievable |
| **Gap** | No agent-to-agent communication protocol |
| **shisad approach** | In shisad's model, this would be a permission escalation: the request from a `guest`-role user triggers a confirmation gate that routes to the `owner` for approval. Same outcome, different mechanism. |
| **Security notes** | Escalation must not bypass PEP. The escalated action still runs under the requester's trust context with explicit owner confirmation. |

#### 9.3 Phone-Number-Based Identity Routing

**What**: Lobster identifies users by phone number (iMessage) and routes to appropriate agent/permission set.

| Aspect | Status |
|--------|--------|
| **shisad support** | Present (v0.3): `ChannelIdentityMap` maps external IDs to internal `(user_id, workspace_id, trust_level)` |
| **Gap** | None — this is supported via `SHISAD_CHANNEL_IDENTITY_ALLOWLIST` |
| **Security notes** | Default-deny for unknown identities. Pairing decisions are audited. |

---

### 10. Proactive Briefings & Scheduled Reports

#### 10.1 Automated Morning Briefing

**What**: Every day at 8am, assistant sends a summary: today's calendar, top news stories, weather, important emails, task reminders — all in one message, "5 minutes to read."

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial (v0.3): scheduler + channel delivery exists; individual data sources partially available |
| **Gap** | No multi-source aggregation skill. Calendar and email connectors missing. Weather/news require web search (available). |
| **Needed** | "Briefing" skill that orchestrates multiple data sources (calendar, email, web search, todos) into a single formatted message, delivered via cron. Requires calendar + email connectors (v0.7). A basic version using web search + todos could work today. |
| **Security notes** | Cron task runs under capability snapshot. Each data source fetch is a separate tool call through PEP. Aggregated output may contain PII from multiple sources — Output Firewall applies. Email content in briefing is tainted. |

#### 10.2 Weekly Retrospective / Scheduled Reports

**What**: "Every Friday at 5pm, summarize everything I accomplished this week — pull from calendar, emails, and GitHub commits."

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: scheduler exists; git tools exist (`git.log`); calendar/email missing |
| **Gap** | No multi-API data gathering (Google Analytics, GitHub API, email, calendar). No report template/formatting system. |
| **Needed** | Report aggregation skill with configurable data sources and output templates. Each API integration is a separate connector/skill. |
| **Security notes** | Same as 10.1: multi-source aggregation under capability snapshot. GitHub API access needs credential broker. Report content may contain sensitive project data — delivery channel must be trusted. |

---

### 11. Content Creation & Drafting

#### 11.1 Newsletter / Blog Drafting (Style Learning)

**What**: User provides writing samples; assistant learns their style. Throughout the week it analyzes content the user interacts with and proactively generates draft newsletters/posts.

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: session memory + notes can store style preferences; no proactive draft generation |
| **Gap** | No "style profile" in memory system. No proactive content generation workflow. No content monitoring ("what you interacted with this week"). |
| **Needed** | Memory: style preference storage (semantic memory). Proactive: triggered/scheduled task that generates drafts. Content monitoring: would require integration with browser history or content feeds. |
| **Security notes** | Style profiles are PII (writing fingerprint). Proactive generation is a scheduled task under capability snapshot. Content monitoring (browser history, RSS feeds) is untrusted input — taint tracking applies. Generated content must pass Output Firewall before delivery. |

#### 11.2 Audio / Media Content Generation

**What**: "Generate a 10-minute morning meditation focused on productivity" — assistant writes script, uses TTS to generate audio, schedules playback.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing |
| **Gap** | No TTS integration. No audio file generation. No media playback control. |
| **Needed** | TTS skill (OpenAI TTS API, local TTS, etc.). Audio file storage. Playback integration (could combine with Sonos/music control from 7.1). |
| **Security notes** | TTS API is egress (sends text content to external service). Text sent to TTS must pass Output Firewall. Generated audio files need storage/cleanup policy. |

---

### 12. Code Generation & Development Workflows

#### 12.1 Code Generation / Application Building

**What**: "Build me a project management board in React with a Kanban layout" — assistant writes full working application, generates and tests code.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing (deferred to the coding-workflow lane) |
| **Gap** | Coding workflows are "across the line" in v0.3. No IDE integration, no code execution environment. |
| **Needed** | Coding agent workflow: proposal/apply contract, sandboxed execution environment, deterministic validator gates, bounded filesystem access. |
| **Security notes** | Code generation + execution is the highest-risk capability. Tainted input (web content, email) could influence generated code to include backdoors, exfiltrate data, or damage the system. Requires: sandboxed execution, proposal-only with human review, no auto-apply, bounded path policy, adversarial tests. |

#### 12.2 Remote System Operations / DevOps from Mobile

**What**: Run shell commands, check disk usage, trigger deployments, manage server configs — all from phone via messaging app. "List large files in ~/Downloads and move PDFs to ~/Documents." Monitor CI/CD pipelines, triage production incidents.

| Aspect | Status |
|--------|--------|
| **shisad support** | Present (v0.3): `fs.read/write` + `git.status/diff/log` + shell execution (confirmation-gated) |
| **Gap** | No CI/CD integration (GitHub Actions, Jenkins). No server health monitoring (disk/CPU/RAM). No SSH-to-remote-host capability. |
| **Needed** | Server monitoring skill (threshold-based alerts). CI/CD API skill (GitHub Actions, etc.). Remote host management requires SSH credential in credential broker. |
| **Security notes** | Shell execution is high-risk and confirmation-gated. Remote SSH expands blast radius significantly. Server monitoring (read-only) is lower risk. CI/CD triggers are side-effecting (confirmation-gated). All shell output is untrusted. |

#### 12.3 Autonomous Task Execution (Kanban/Project Management)

**What**: "Work through my backlog — pick tasks, complete them, move to done, report status daily." Assistant autonomously picks tasks from Linear/Notion/Trello and works through them.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing |
| **Gap** | No project management API integration (Linear, Notion, Trello). No autonomous multi-step task execution loop. |
| **Needed** | Project management API skill + autonomous execution loop with daily status reporting. Each task execution step goes through PEP. |
| **Security notes** | Autonomous execution is extremely high-risk. Each task from the backlog is effectively untrusted input (could be crafted to trigger injection). Must use commit-before-contamination: read task description, commit plan, then execute. Must have kill switch / rate limiting. Daily reports via trusted channel. |

---

### 13. Multimodal Input & Processing

#### 13.1 Voice Commands / Voice Notes

**What**: User sends voice messages; assistant transcribes and acts on them. Or uses voice-enabled hardware (e.g., smart glasses) to interact.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing (deferred to the attachment pipeline lane) |
| **Gap** | No speech-to-text pipeline. No voice message handling in channel adapters. |
| **Needed** | STT skill (Whisper API or local Whisper). Channel adapter support for voice message attachments. Transcription → text pipeline that feeds into normal message processing. |
| **Security notes** | Voice transcription is untrusted input (adversarial audio injection is a known attack vector). Transcribed text must go through ContentFirewall. STT API call is egress. |

#### 13.2 Voice Telephony (Outbound Calls)

**What**: "Book a table at that Italian place for 7pm Friday" — assistant makes an actual phone call using TTS + telephony APIs (ElevenLabs + Twilio) to book restaurant reservations, appointments, etc.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing |
| **Gap** | No telephony integration. No outbound call capability. |
| **Needed** | Telephony skill (Twilio API for calls/SMS). TTS for voice synthesis. Call script generation. Call outcome parsing. |
| **Security notes** | Outbound phone calls are irreversible public-facing egress. Must be confirmation-gated with full script review. Voice impersonation risk (calling "as" the user). Telephony API credentials via credential broker. Cost controls needed (calls cost money). |

#### 13.3 Meeting Transcription & Action Extraction

**What**: Upload meeting recording → assistant transcribes, extracts action items with owners and deadlines.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing (requires attachment pipeline + STT) |
| **Gap** | No audio file upload handling. No long-form transcription. No structured action item extraction. |
| **Needed** | Attachment pipeline for audio files. Long-form STT (Whisper). LLM-driven action item extraction with structured output. |
| **Security notes** | Meeting recordings contain sensitive business content. Transcription via external API is egress of sensitive data. Local transcription (Whisper) preferred. Extracted action items may contain PII. |

#### 13.4 Image Recognition & Processing

**What**: Take a photo of a recipe → assistant extracts ingredients. Or photograph a product → assistant finds it online with price comparison.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing (deferred to the attachment pipeline lane) |
| **Gap** | No image attachment handling. No vision model integration. No OCR pipeline. |
| **Needed** | Attachment pipeline (receive, store, process). Vision model integration (multimodal LLM or dedicated vision API). Structured extraction from images. |
| **Security notes** | Images are untrusted input (adversarial images with embedded text/instructions are a known injection vector). Vision model output must be treated as tainted. Image processing is egress if using external API. Local processing preferred for sensitive images. |

---

### 14. Data Processing & Knowledge Bases

#### 14.1 Bulk Chat/Document Ingestion

**What**: Connect chat history (WhatsApp export, Slack archive) → assistant ingests, processes, and creates searchable knowledge base. Transcribes voice messages. Links discussions to code commits.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing |
| **Gap** | No bulk data ingestion pipeline. No document processing (PDF, chat export formats). No cross-referencing/linking system. |
| **Needed** | Ingestion skill: parse chat exports / documents, chunk, embed, store in memory with provenance. STT for voice messages. Entity extraction and cross-referencing. |
| **Security notes** | Bulk ingestion is a major poisoning vector. All ingested content is untrusted. Must go through ContentFirewall before indexing. Taint must persist in stored embeddings/summaries. Ingestion should be rate-limited and operator-confirmed. PII in chat history needs redaction policy. |

---

### 15. Shopping & Commerce

#### 15.1 Grocery / Shopping Automation

**What**: Photo of recipe → extract ingredients → check prices/availability → place order with delivery service.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing |
| **Gap** | No image processing (see 13.2). No grocery/commerce API integration. No payment/ordering capability. |
| **Needed** | Vision model for ingredient extraction. Grocery API skill (Instacart, Amazon Fresh, etc.). Payment requires stored credentials and explicit confirmation. |
| **Security notes** | Ordering/payment is the highest-risk commerce action. Must be multi-step confirmation: show extracted items → confirm list → confirm total → place order. Stored payment credentials via credential broker only (never in LLM context). Injection via recipe image could add items or change delivery address. |

#### 15.2 Price Comparison / Product Search

**What**: See a product → "What's this on Amazon?" → assistant identifies product, searches, compares prices.

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: `web.search` + `web.fetch` can do basic product research |
| **Gap** | No image recognition (see 13.2). No structured product search APIs. No cart/purchase integration. |
| **Needed** | Vision model for product identification. Product search API skills. Cart addition is commerce action (see 15.1). |
| **Security notes** | Product search via web is standard web fetch (ContentFirewall applies). Cart/purchase actions require confirmation. |

---

### 16. Monitoring & Alerts

#### 16.1 Health & Fitness Dashboard

**What**: Connect WHOOP, Oura, Apple HealthKit → get daily fitness breakdown delivered to messaging app.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing |
| **Gap** | No wearable/health API integrations |
| **Needed** | Health API connector skills (WHOOP API, Oura API, Apple HealthKit). Scheduled report delivery (see 10.2). |
| **Security notes** | Health data is highly sensitive PII. API credentials via credential broker. Health data summaries must not leak to untrusted channels. Storage/retention policy required. HIPAA-adjacent considerations for US users. |

#### 16.2 Financial Alerts (Stock Prices, Crypto)

**What**: "Alert me if Tesla drops 5% or Apple hits $200" → instant notification via scheduled monitoring.

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: scheduler exists; web fetch can check prices |
| **Gap** | No financial API integration. No threshold-based alerting system. |
| **Needed** | Financial API skill (Yahoo Finance, Alpha Vantage, etc.) or web scraping. Triggered task: poll at interval, compare against threshold, deliver alert. |
| **Security notes** | Financial data is sensitive. Low egress risk (read-only API calls). Alert delivery to trusted channel only. Polling frequency must be rate-limited (API quotas). |

#### 16.3 News & Keyword Monitoring

**What**: Set up keyword tracking for topics/competitors → get digest every morning.

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial (v0.3): `web.search` + scheduler can do basic keyword monitoring |
| **Gap** | No dedicated news monitoring skill. No keyword watch list management. No digest formatting. |
| **Needed** | Keyword watchlist (stored in notes/memory). Scheduled search task. Digest aggregation and formatting skill. |
| **Security notes** | Web search results are untrusted. Digest content is tainted. Standard ContentFirewall + Output Firewall applies. |

---

### 17. Professional & Business Workflows

#### 17.1 Customer Support Agent

**What**: Handle incoming WhatsApp/email customer messages → auto-reply using AI, escalate complex issues to human.

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: channel adapters + session management exist; auto-reply logic possible |
| **Gap** | No customer-facing agent mode. No escalation workflow. No CRM integration. |
| **Needed** | Customer-facing agent persona with restricted tool access. Escalation trigger (confidence threshold, keyword detection, explicit request). CRM skill for customer context lookup. |
| **Security notes** | Customer messages are untrusted (injection vector). Auto-reply to external parties is high-risk egress. Must be heavily constrained: no internal data exposure, no tool access beyond knowledge base lookup, mandatory escalation for anything ambiguous. Output Firewall critical. |

#### 17.2 Social Media Management

**What**: Monitor social media mentions → respond to comments → generate daily engagement reports.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing |
| **Gap** | No social media API integrations (X/Twitter, Instagram, LinkedIn, etc.) |
| **Needed** | Social media API skills (read: mention monitoring; write: post/reply). Scheduled monitoring + reporting. |
| **Security notes** | Social media posting is public-facing irreversible egress. Must be confirmation-gated. Monitoring feeds are untrusted input (injection via crafted mentions/comments is trivial). Auto-reply to social media is extremely high-risk. |

#### 17.3 Personal CRM / Relationship Management

**What**: Track relationships, log interactions, coordinate outreach, send follow-ups. Get pre-meeting briefs with context from email/calendar/CRM history.

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: notes/memory can store contact info; no structured CRM |
| **Gap** | No CRM data model. No interaction logging. No automated outreach. No pre-meeting brief generation. |
| **Needed** | CRM skill with contact entities, interaction log, relationship scoring. Integration with calendar (pre-meeting) and email (outreach). Automated follow-up scheduling. |
| **Security notes** | CRM data is PII-heavy. Automated outreach is egress (confirmation-gated). Pre-meeting briefs aggregate tainted data from multiple sources. Contact data must not leak between workspaces/users. |

#### 17.4 Job Search Automation

**What**: Cron job scrapes new postings each morning, tracks applications in database, preps for interviews, monitors email for responses.

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: web search + scheduler exist |
| **Gap** | No job board API integration. No application tracking database. No interview prep workflow. |
| **Needed** | Job search skill (web scraping or API-based). Application tracker (could build on notes/todos). Email monitoring for responses (requires email connector). |
| **Security notes** | Job postings are untrusted web content (ContentFirewall). Application tracking contains PII. Auto-applying to jobs would be extremely high-risk egress (not recommended without manual confirmation per application). |

---

### 18. Education & Learning

#### 18.1 Language Learning Assistant (Agentic)

**What**: Chat in target language → assistant corrects grammar, explains idioms, sends weekly vocabulary quizzes. Proactively chases the user down if they haven't practiced.

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: conversational capability exists; no dedicated language learning workflow |
| **Gap** | No structured learning curriculum. No quiz generation/scheduling. No progress tracking. No proactive "chase-down" nudging. |
| **Needed** | Language learning skill with: grammar correction mode, vocabulary tracker (memory), scheduled quizzes (scheduler), progress reporting, inactivity detection + nudge messages. Integration with existing learning systems (e.g., custom SRS/curriculum repos). This now fits the post-`v0.7` memory-enabled lane, not locked `v0.4`. |
| **Concrete example** | A structured language-learning curriculum repo or SRS system that would benefit from an agentic wrapper: proactive scheduling, "chase-down" reminders if the user has not practiced, and voice interaction for pronunciation practice. |
| **Security notes** | Low-risk use case. All content is user-generated or LLM-generated. Standard memory write-gating for vocabulary/progress storage. Nudge messages are outbound to trusted user channel (low egress risk). |

---

### 19. Content Pipeline & Quality Control

#### 19.1 Multi-Agent Content Pipeline with Quality Gates

**What**: Writer agent generates drafts → Editor agent scores them against a rubric → below-threshold drafts are rejected or sent back. Pipeline manager monitors the content queue. ~40% rejection rate indicates a real quality bar.

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: multi-model routing exists (planner/monitor/embeddings); no multi-agent content pipeline |
| **Gap** | No multi-agent pipeline orchestration. No quality scoring rubric system. No draft queue/state machine. |
| **Needed** | Content pipeline skill: sequential agent handoff (writer → editor → publisher), configurable scoring rubric, rejection/revision loop, queue management. Model routing: use cheaper models (Haiku-class) for automated tasks, capable models for judgment. |
| **Security notes** | Inter-agent handoff must preserve taint tracking. Editor agent's scoring criteria must be in the trusted control plane (not modifiable by tainted content). Published content is egress — confirmation-gated. |

---

### 20. Location & Dining

#### 19.1 Restaurant Check-In & Menu Logging

**What**: At a restaurant, send photos of menus/food to assistant. Assistant logs what you ordered, your ratings, GPS/check-in location. Uses Google Maps or Swarm/Foursquare check-in data. Next time you visit, reminds you what you had and whether you liked it.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing |
| **Gap** | No image processing (see 13.2). No location/GPS integration. No Google Maps / Swarm API. No restaurant/dining memory model. |
| **Needed** | Vision model for menu/food photo processing. Location API integration (Google Maps, Swarm/Foursquare). Dining memory model: restaurant → visits → items ordered → ratings. Triggered recall: when near a previously-visited restaurant or when user mentions it, surface past orders/ratings. Voice interaction for hands-free logging while dining. |
| **Security notes** | Location data is sensitive PII. Photo metadata (EXIF GPS) needs privacy-aware handling. Restaurant/dining preferences are PII. Third-party API calls (Google Maps, Swarm) are egress — credential broker + allowlist. Voice input is untrusted (see 13.1). |

#### 19.2 Location-Aware Recommendations & Recall

**What**: "What did I order last time at that ramen place?" or "I'm near Shibuya, any restaurants I've liked around here?" — assistant queries dining memory by location or restaurant name.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing |
| **Gap** | No location-aware memory retrieval. No geospatial search in memory system. |
| **Needed** | Geospatial indexing in memory (lat/lng on dining entries). Location-triggered context retrieval. Could also integrate with maps for "nearby" queries. |
| **Security notes** | Location queries reveal user's current position — delivery channel must be trusted. Geospatial data is PII subject to retention/deletion controls. |

---

### 21. Personal Finance & Accounting

#### 21.1 Expense Tracking & Spending Queries

**What**: "How much did I spend on rideshares this month?" — assistant queries against personal accounting data (plain-text accounting like hledger, or bank export data).

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: `fs.read` can read local ledger files; no accounting query tool |
| **Gap** | No accounting/finance query skill. No bank API integration. No structured financial data model. |
| **Needed** | Finance query skill: parse hledger/CSV/OFX files, run structured queries. Bank API integration (Plaid, etc.) for live data. |
| **Security notes** | Financial data is highly sensitive. Must stay local (no external API calls unless explicitly configured). Query results may contain account numbers — Output Firewall applies. |

#### 21.2 Receipt Processing (Photo → Spreadsheet)

**What**: Photograph a receipt → assistant extracts merchant, items, amounts → writes to expense spreadsheet.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing (requires image processing, see 13.4) |
| **Gap** | No image attachment handling. No OCR/vision for receipts. No spreadsheet integration. |
| **Needed** | Vision model for receipt parsing. Structured extraction (merchant, line items, total, date). Export to spreadsheet/CSV. |
| **Security notes** | Receipts contain PII (card numbers, addresses). Vision API call is egress of sensitive data — prefer local processing. Extracted data stored locally with PII controls. |

---

### 22. Document & File Management

#### 22.1 Document Filing & Auto-Organization

**What**: Send photo/PDF → assistant OCRs, renames with meaningful name, files in correct folder (e.g., family documents → organized Google Drive/local folders).

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: `fs.write` can create/move files (confirmation-gated) |
| **Gap** | No attachment/PDF processing. No OCR. No auto-classification. No Google Drive integration. |
| **Needed** | OCR skill (Tesseract or vision model). Document classification (LLM-driven). File organization rules. Cloud storage API skill (Google Drive, Dropbox). |
| **Security notes** | Document content is untrusted (injection via crafted PDFs is a known vector). OCR output must go through ContentFirewall. Cloud storage API is egress — credential broker + allowlist. File moves are side-effecting (confirmation-gated). |

#### 22.2 Directory Monitoring & Auto-Processing

**What**: Watch a directory for new files → automatically process, rename, organize, or alert. "When a new PDF appears in ~/Downloads, file it appropriately."

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: scheduler exists; `fs.list` + `fs.read` available |
| **Gap** | No filesystem event monitoring (inotify/fsevents). Polling via cron is possible but not native. |
| **Needed** | File watcher skill or cron-based directory scanning. Auto-classification + filing pipeline (see 22.1). This is no longer a `v0.4` item; it fits the later tool-surface / ingestion lane. |
| **Security notes** | Files appearing in watched directories are untrusted input. Auto-processing of untrusted files is high-risk (malicious files, injection via filenames/content). Must be bounded: file type allowlist, size limits, sandboxed processing. |

---

### 23. Media & Entertainment

#### 23.1 Media Server Management (Plex/Jellyfin)

**What**: "Add the new Lanthimos movie to my library" — assistant searches for a movie/show, submits request to Radarr/Sonarr/Jellyseerr, media appears in Plex/Jellyfin when downloaded.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing |
| **Gap** | No media server API integration |
| **Needed** | Media management skill: Jellyseerr/Radarr/Sonarr API. Search + request workflow. Status tracking. |
| **Security notes** | Media server APIs are local network egress — allowlist. API keys via credential broker. Low-risk (no PII, reversible actions). Content search is untrusted if using web sources. |

#### 23.2 Bookmark & Link Management (Semantic Search)

**What**: Save articles/tweets/links → assistant indexes with embeddings → "What did I save about sleep optimization?" returns semantically relevant bookmarks.

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: notes can store links; no semantic search over bookmarks |
| **Gap** | No bookmark ingestion pipeline. No embedding-based search over saved links. No browser extension or API integration for bookmark capture. |
| **Needed** | Bookmark ingestion skill (import from browser, Pocket, Raindrop, or manual save). Embedding + vector search. Retrieval tool for semantic queries. |
| **Security notes** | Bookmarked content is untrusted (web content). Ingestion goes through ContentFirewall. Embeddings preserve taint. Retrieval returns sanitized results with provenance. |

---

### 24. Knowledge Management & Personal Knowledge Base

#### 24.1 Voice-to-Journal

**What**: Send voice note via messaging app → assistant transcribes → structures into daily journal entry → auto-commits to notes/git.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing (requires STT, see 13.1) |
| **Gap** | No voice note handling. No journal structure/template system. No auto-commit workflow. |
| **Needed** | STT (Whisper) for transcription. Journal template skill. Git integration for auto-commit of journal entries. |
| **Security notes** | Voice content is untrusted input. Transcription API is egress. Journal entries may contain PII — stored locally with standard memory write-gating. Git push is egress (confirmation-gated or pre-authorized). |

#### 24.2 Personal Knowledge Base / RAG / "Second Brain"

**What**: Ingest URLs, articles, tweets, notes → build searchable knowledge base with embeddings → query from chat: "What do I know about X?"

| Aspect | Status |
|--------|--------|
| **shisad support** | Planned (architecture designed): memory hierarchy with semantic search via embeddings |
| **Gap** | Memory system not yet runtime-wired. No bulk URL ingestion. No web content indexing pipeline. |
| **Needed** | Memory hierarchy implementation. Web content ingestion skill (fetch, parse, chunk, embed). Query interface over personal knowledge base. |
| **Security notes** | All ingested web content is untrusted. Must go through ContentFirewall before indexing. Taint persists in embeddings. RAG retrieval returns sanitized evidence with provenance + risk score. This is exactly what shisad's memory architecture is designed for. |

#### 24.3 Private Document Assistant (Local RAG)

**What**: Query local files (PDFs, notes, code) using local LLM (Ollama) without any data leaving the machine.

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: `fs.read` available; local model routing supported |
| **Gap** | No local RAG pipeline. No document chunking/embedding for local files. |
| **Needed** | Local RAG skill: index local files, chunk, embed (local embedding model), vector search. Query tool. |
| **Security notes** | This is the most privacy-friendly pattern — no egress at all. Local model + local embeddings + local storage. shisad's model routing already supports local endpoints. |

---

### 25. Family & Household Coordination

#### 25.1 Family Calendar Aggregation & Announcements

**What**: Aggregate family members' calendars → morning announcements ("Alex has soccer at 3pm, dinner reservation at 7pm"). Deliver via messaging, Alexa/speaker, or smart display.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing (requires calendar connector, see 3.1) |
| **Gap** | No multi-calendar aggregation. No smart speaker/display output. |
| **Needed** | Calendar connectors (multiple accounts). Announcement skill with multi-channel delivery (messaging + optional TTS to speakers). |
| **Security notes** | Multi-person calendar data is PII. Each calendar credential independently scoped. Announcement content may contain family PII — delivery to trusted channels only. |

#### 25.2 Household Task Coordination

**What**: "Thursday dinner — check everyone's preferences and start a poll." Coordinate chores, errands, meals with polls and reminders to family members.

| Aspect | Status |
|--------|--------|
| **shisad support** | Partial: cross-user messaging (1.3) + reminders (4.1) would enable this |
| **Gap** | No polling/voting mechanism. No household task assignment system. |
| **Needed** | Poll skill (send options to family group chat, collect votes). Household task tracker (shared todo list with assignment). Meal planning integration. |
| **Security notes** | Low-risk (intra-family communication). Standard channel security applies. Poll responses from group chat are untrusted input. |

---

### 26. Browser Automation

#### 26.1 Form Filling & Web Admin Tasks

**What**: Fill out forms, log into web tools, automate repetitive web-based admin tasks that don't have APIs.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing (deferred to the browser-automation lane) |
| **Gap** | No browser automation tool. Browser executor exists (`src/shisad/executors/browser.py`) but not wired as a user-facing skill. |
| **Needed** | Browser automation skill (Playwright-based). Page interaction tools (navigate, click, fill, extract). Session management for authenticated sites. |
| **Security notes** | Browser automation is extremely high-risk: highest prompt-injection pressure (web pages are untrusted), credential exposure (logging into sites), action surface (can do anything a human can in a browser). Requires: sandboxed browser, action confirmation, URL allowlisting, no credential exposure to LLM context. Target: **v0.7**. |

---

### 27. Google Workspace & Cloud Productivity

#### 27.1 Google Docs/Sheets/Slides Editing

**What**: "Update cell B3 in my budget spreadsheet to $450" or "Add a slide about Q3 results to the deck" — assistant edits Google Workspace documents from chat.

| Aspect | Status |
|--------|--------|
| **shisad support** | Missing |
| **Gap** | No Google Workspace API integration |
| **Needed** | Google Workspace skill: Docs API (read/edit), Sheets API (read/write cells), Slides API. OAuth credential via credential broker. |
| **Security notes** | Document editing is side-effecting (confirmation-gated). Google OAuth scope must be minimal (per-API). Document content is a mix of trusted (user's docs) and potentially untrusted (shared docs). Edits to shared documents are externally visible — extra caution needed. |

---

### 28. Self-Extending Agent (Meta-Pattern)

#### 28.1 Agent Writes Its Own Skills

**What**: Describe what you need → agent drafts a new skill definition (manifest + code) → user reviews and enables it. "I need to query our internal API and post results to Slack" → agent creates the skill.

| Aspect | Status |
|--------|--------|
| **shisad support** | Deliberate divergence: clean-room workflow exists for admin-reviewed skill proposals, but no self-modification |
| **Gap** | No "agent creates skill" workflow. This is intentional — self-modification is a security anti-pattern. |
| **shisad approach** | shisad's v0.3 clean-room workflow supports proposal artifacts (diffs, manifests) but never auto-applies. Skill creation is an admin-reviewed process. The agent can *propose* a skill, but installation requires operator review via trusted admin surface. |
| **Security notes** | Self-extending agents are a major supply-chain and integrity risk. An injected prompt could cause the agent to create a malicious skill that persists beyond the current session. shisad explicitly avoids this by design. The proposal-only pattern preserves the utility (agent can draft skills) while maintaining security (human reviews before activation). |

---

## Gap Summary by Priority

### Already Supported (v0.3)

| Use Case | shisad Feature |
|----------|---------------|
| Direct chat via messaging apps | Discord, Telegram, Slack, Matrix channels |
| Identity-based routing | `ChannelIdentityMap` + default-deny allowlist |
| Create reminders | `todo.create` + scheduler + channel delivery |
| Persistent lists (shopping, packing) | `note.create` + `note.list` (basic; no structured list ops) |
| Web research (search + fetch + summarize) | `web.search` + `web.fetch` (config-gated, allowlisted) |
| Clarifying questions / multi-turn | Session-based conversation |
| Notes / knowledge capture | `note.create` + `note.list` |
| Filesystem / git workflows | `fs.read/write` + `git.status/diff/log` |
| Per-user trust levels | `UserRole` + PEP enforcement |
| Basic keyword/news monitoring | `web.search` + scheduler (manual setup) |
| Basic financial price checking | `web.fetch` + scheduler (manual setup) |
| Language learning chat | Conversational capability (no structured curriculum) |
| Remote shell/fs ops from mobile | `fs.read/write` + shell execution (confirmation-gated) |
| Local document queries | `fs.read` + local model routing |
| Price comparison (basic) | `web.search` + `web.fetch` |

### Requires New Skills/Connectors (future tool-surface scope)

| Use Case | What's Needed | Target | Security Considerations |
|----------|--------------|--------|------------------------|
| Email read/triage | IMAP/OAuth connector | v0.7 | Major injection vector; taint all email content |
| Email send/draft | SMTP/OAuth + confirmation gate | v0.7 | Irreversible egress; confirmation-gated |
| Email bulk actions (unsubscribe, auto-reply) | Email connector + bulk action tools | v0.7 | Bulk auto-reply is high-risk; per-batch confirmation |
| Calendar read | CalDAV/Google Calendar API | v0.7 | Credential broker; PII in event data |
| Calendar write | Calendar API + confirmation | v0.7 | Side-effecting; confirmation-gated |
| Morning briefing (full) | Multi-source aggregation skill | v0.7 | Aggregates tainted data; Output Firewall applies |
| Weekly retrospective / reports | Multi-API data gathering | v0.6+ | GitHub/calendar/email APIs; credential broker |
| Package tracking | Email monitoring + tracking API | v0.6+ | Triggered task; capability snapshot |
| Music control (Sonos/Spotify) | Sonos API / Spotify API skill | v0.6+ | Local network egress; OAuth |
| Smart home (Hue, etc.) | HomeAssistant/Hue API skill | v0.6+ | Safety-relevant actions; per-device policy |
| Cross-user message relay | User-facing `message.send` + user/channel routing | v0.5+ | Confirmation-gated; allowlisted destinations |
| Cross-user reminders | Cross-user delivery path | v0.5+ | Same as message relay |
| Flight tracking | FlightAware API skill | v0.6+ | API credential management |
| Health/fitness dashboard | WHOOP/Oura/HealthKit API skills | v0.6+ | Highly sensitive PII; credential broker |
| Financial alerts | Financial API skill | v0.6+ | Sensitive data; rate-limited polling |
| Social media management | Social media API skills | v0.6+ | Public-facing egress; confirmation-gated |
| Personal CRM | CRM data model + integrations | v0.6+ | PII-heavy; outreach is egress |
| Customer support agent | Customer-facing agent mode | v0.6+ | Untrusted input; auto-reply is high-risk egress |
| Grocery/shopping automation | Commerce API skills + payment | v0.6+ | Payment is highest-risk commerce action |
| TTS / audio generation | TTS API skill | v0.6+ | Text sent to TTS is egress |
| Job search automation | Job board APIs + tracker | v0.6+ | PII; auto-apply is high-risk |
| Restaurant/dining logging | Vision + location APIs + dining memory | v0.6+ | Location is sensitive PII; photo EXIF privacy |
| Location-aware recall | Geospatial indexing in memory | v0.7+ | Reveals user position; trusted channel only |
| Voice telephony (outbound calls) | Twilio + TTS APIs | v0.6+ | Irreversible public-facing egress; voice impersonation risk |
| Meeting transcription | Long-form STT + action extraction | v0.6+ | Sensitive business content; prefer local STT |
| Receipt processing | Vision + OCR + spreadsheet export | v0.6+ | Receipts contain card numbers; prefer local processing |
| Document filing / OCR | Vision/OCR + auto-classification | v0.6+ | Untrusted PDFs are injection vector |
| Directory monitoring | File watcher / cron-based scanning | v0.6+ | Auto-processing untrusted files is high-risk |
| Media server (Plex/Jellyfin) | Radarr/Sonarr/Jellyseerr API | v0.6+ | Local network egress; low-risk |
| Bookmark / link search | Ingestion pipeline + embedding search | v0.7+ | Web content is untrusted; taint persists |
| Voice-to-journal | STT + journal template + git | v0.6+ | Voice is untrusted; transcription API is egress |
| Personal knowledge base / RAG | Memory hierarchy + web ingestion | v0.7+ | All ingested content untrusted; ContentFirewall |
| Family calendar aggregation | Multi-calendar connectors | v0.6+ | Multi-person PII; per-credential scoping |
| Household task coordination | Poll skill + shared todos | v0.7+ | Low-risk; standard channel security |
| Google Workspace editing | Google Docs/Sheets/Slides API | v0.6+ | Side-effecting; OAuth scope minimization |
| Server health monitoring | Monitoring skill (disk/CPU/RAM) | v0.6+ | Read-only; low-risk |
| CI/CD monitoring | GitHub Actions / Jenkins API | v0.6+ | Build triggers are side-effecting |
| Expense tracking / finance queries | Finance query skill | v0.6+ | Highly sensitive; keep local |
| Content repurposing | Multi-format adaptation skill | v0.6+ | Social posting is public egress |

### Requires Architectural Work

| Use Case | What's Needed | Target | Notes |
|----------|--------------|--------|-------|
| Group chat @mention gating | Per-channel routing rules | v0.7 (stretch) | Config-driven, but now coupled to group-scoped policy/routing work |
| Memory / preference learning | Memory hierarchy implementation | v0.7+ | Core architecture designed but not runtime-wired |
| Automatic fact extraction | LLM-driven extraction pipeline | v0.7+ | Effectively part of the memory/extraction lane because the writes need the gated memory stack, not locked `v0.4` |
| Streaming/chunked replies | TUI/Web UI progress + status streaming over the daemon event stream | v0.8 | Reframed as operator UX for TUI/Web UI, not token streaming for Discord/Telegram-style messaging channels |
| Voice/speech input (STT) | Attachment pipeline + Whisper | v0.7 | Adversarial audio is injection vector |
| Image/vision input | Attachment pipeline + vision model | v0.7 | Adversarial images are injection vector |
| Code generation / dev workflows | Sandboxed execution + proposal/apply | v0.4 | Highest-risk capability; needs full review |
| Autonomous task execution | Multi-step execution loop + kill switch | v0.5 | Extremely high-risk; commit-before-contamination |
| Content/newsletter drafting | Style profile in memory + proactive gen | v0.6+ | Needs memory hierarchy + scheduled tasks |
| Bulk data ingestion | Ingestion pipeline + ContentFirewall | v0.6+ | Major poisoning vector; rate-limited |
| Browser automation | Playwright + sandboxed browser | **v0.7** | Highest injection pressure; URL allowlisting |
| Self-extending agent (write own skills) | Clean-room proposal workflow | Present (v0.3) | Deliberate: proposal-only, no auto-apply |

### Deliberate Divergences (Not a Gap)

| Lobster Approach | shisad Approach | Why |
|-----------------|----------------|-----|
| Separate Docker-sandboxed agents per role | Per-identity capability scoping via PEP | Centralized policy enforcement is stronger than per-container policy |
| iMessage as primary channel | Discord/Telegram/Slack/Matrix | iMessage lacks stable bot API; shisad uses protocols with official bot support |
| Agent-to-agent escalation | Permission escalation with owner confirmation | Same security outcome via PEP rather than inter-process communication |
| Dedicated MacBook Air hardware | Any Linux/macOS server | shisad is platform-agnostic; systemd service model |

### Cannot Support / Needs Workaround

| Use Case | Issue | Workaround |
|----------|-------|-----------|
| iMessage channel | No stable official bot API | Use Telegram/Discord/Slack instead; or iMessage-to-Matrix bridge (adds trust surface) |
| Parcel app integration | macOS-only app; no API | Use web-based tracking service instead; or shell automation on macOS |
| Apple Calendar/Reminders | macOS-only APIs (AppleScript/Shortcuts) | Use CalDAV (works with iCloud) or Google Calendar |

---

## Operational Lessons from Real Deployments

Based on a [3-week OpenClaw daily driver report](https://www.reddit.com/r/LocalLLaMA/comments/1r3ro5h/3_weeks_with_openclaw_as_daily_driver_what_worked/), these are failure patterns and design lessons that shisad's architecture should address:

### The "Dory Problem" (Cron Jobs Lack Session Context)

**Problem**: Scheduled tasks have no memory of what happened in the main session. User says "cancel that follow-up" but a cron fires days later because it was scheduled before the cancellation.

**shisad relevance**: shisad's task system uses capability snapshots captured at creation time — but there's no mechanism for session-side cancellations to propagate to scheduled tasks. Need: a `DECISIONS.md`-style override check, or task cancellation propagation from session to scheduler.

**shisad advantage**: Our scheduler already has explicit cancel semantics (`task.cancel`). The architectural gap is ensuring the LLM reliably invokes cancel when the user says "never mind" about a previously-scheduled action.

### Output Sanitization (Internal Reasoning Leaks)

**Problem**: Cron job output includes the agent's internal reasoning ("Now I'll check the calendar and then send a message...") instead of clean user-facing output. Embarrassing messages sent to contacts.

**shisad relevance**: shisad separates inner monologue from user-visible output by design. But scheduled task output delivery needs explicit output formatting — the delivered message should be the final assistant response only, not the full execution trace.

**shisad advantage**: Output Firewall already exists for PII/secret filtering. Extending it to strip reasoning traces from scheduled delivery is straightforward.

### Sub-Agent Context Contamination

**Problem**: Sub-agents load cached context files and act on stale information (e.g., "credentials expired!" based on old memory, even though already fixed in main session).

**shisad relevance**: This is a memory consistency problem. shisad's memory system should distinguish between "last known state" and "verified current state." Sub-agents for verification tasks should re-check live state, not trust cached memory.

**shisad advantage**: Taint tracking and provenance metadata can include freshness/staleness signals. Memory retrieval can flag stale entries.

### Timestamp Calculation Errors

**Problem**: LLM calculated Unix timestamps "mentally" — wrote "2025" instead of "2026", creating past timestamps that fired immediately.

**shisad relevance**: shisad should never let the LLM compute timestamps directly. Schedule parsing should use validated datetime libraries, not raw LLM output. The scheduler should reject past timestamps.

**shisad advantage**: Already addressed by design — scheduler uses structured `datetime` objects, not raw strings.

### Automation Guardrails (Key Principle)

> "Automation without guardrails creates more problems than it solves."

Every scheduled task that takes external action needs:
1. **Pre-flight check**: Is this still relevant? (Check for overrides/cancellations)
2. **Output sanitization**: No internal reasoning leaking
3. **Abort mechanism**: If context changed since scheduling

This aligns directly with shisad's capability snapshot + PEP enforcement model.

---

## Security Analysis: Lobster vs shisad

### Where Lobster's Security Model Falls Short

Based on the article and OpenClaw's architecture:

1. **No prompt injection defense**: Lobster reads emails and web content with no content firewall. An attacker could craft an email that instructs Lobster to forward sensitive data.

2. **Docker sandbox is coarse-grained**: Lobster-Family is Docker-sandboxed, but Docker is an infrastructure boundary, not a semantic policy boundary. A compromised model inside the container still has full access to everything the container can reach.

3. **No output filtering**: No mention of PII/secret redaction on outbound messages. The assistant could leak sensitive information from emails into group chats.

4. **No taint tracking**: When Lobster reads an email and then takes an action, there's no tracking of whether the action was influenced by untrusted email content.

5. **Executive agent has unrestricted access**: Lobster (Executive) has full access to everything. A prompt injection via any input channel could potentially leverage this unrestricted access.

### How shisad Would Handle Lobster's Use Cases More Securely

| Use Case | Lobster Risk | shisad Mitigation |
|----------|-------------|-------------------|
| Read & summarize emails | Email content could contain injection | ContentFirewall + taint tracking; email body is `UNTRUSTED` |
| Draft email replies | Tainted context influences reply content | Output Firewall; PII/secret redaction; confirmation gate |
| Relay messages | Injected content forwarded to family | Confirmation gate; allowlisted destinations; output filtering |
| Package tracking from emails | Triggered task with tainted input | Capability snapshot; commit-before-contamination; no auto-egress |
| Smart home control | Injection could trigger physical actions | Per-device confirmation policy; PEP enforcement |
| Group chat responses | Any group member's message is injection vector | ContentFirewall on all inbound; per-user trust levels |

---

## Implementation Roadmap Alignment

| Release | Use Cases Enabled |
|---------|------------------|
| **v0.3** (current) | Chat via Discord/Telegram/Slack, reminders, notes/todos/lists, web search+fetch, filesystem/git, remote shell ops, identity routing, basic monitoring/alerts, skill proposals (self-extending) |
| **Longer-term** | WhatsApp/GChat/LINE via gateway |
| **v0.4** | Proposal-first coding workflows, scheduled task guardrails, and the admin-reviewed surfaces needed to close the loop safely |
| **v0.5** | Public release baseline: evidence references, public docs, licensing, and release-ready runtime validation |
| **v0.6** | Orchestration foundation, multi-turn taint/task handoff, typed delegated execution, safe subagent/task runtime for later assistant surfaces |
| **v0.6.1** | MCP/A2A interop and remote-tool trust work |
| **v0.7** | Email (read/send/triage), calendar (read/write), morning briefings (full), attachment pipeline, browser automation, weekly reports, content drafting, TTS, meeting transcription, voice-to-journal, health/fitness dashboards, financial alerts/queries, receipt processing, document filing/OCR, personal CRM, job search, package tracking, flight tracking, Google Workspace, media server management |
| **v0.6+** | Music control, smart home, grocery/shopping, bulk data ingestion, news monitoring (structured), content repurposing, customer support agent, social media management, voice telephony |
| **v0.7+** | Memory hierarchy, preference learning, personal knowledge base / RAG, bookmark/link search, family calendar aggregation, household coordination, location-aware recall, group chat @mention gating, memory-driven extraction workflows |
| **v0.8** | Operator Web UI, TUI/web progress-status streaming, multitenant deployments |

---

## Full Use Case Status Reference

Complete per-use-case breakdown across all 62 cataloged use cases.

### Supported Today (v0.3) — 7

| # | Use Case | How |
|---|----------|-----|
| 1.1 | Direct chat via messaging apps | Discord, Telegram, Slack, Matrix, CLI |
| 4.1 | Create reminders (natural language) | `todo.create` + scheduler + channel delivery |
| 4.3 | Persistent lists (shopping, etc.) | `note.create` + `note.list` |
| 5.2 | Clarifying questions / multi-turn | Session-based conversation |
| 9.3 | Identity-based routing | `ChannelIdentityMap` + default-deny allowlist |
| 12.2 | Remote shell/fs/git ops from mobile | `fs.read/write` + `git.*` + shell (confirmation-gated) |
| 28.1 | Self-extending agent (skill proposals) | Clean-room proposal workflow (proposal-only, no auto-apply) |

### Partial (Foundation Exists, Needs Skills/Wiring) — 24

| # | Use Case | What Works | What's Missing |
|---|----------|-----------|---------------|
| 1.2 | Group chat @mentions | Channel adapters receive messages | Mention-gating routing rules |
| 4.2 | Cross-user reminders | Scheduler exists | Cross-user delivery path |
| 5.1 | Research flights/topics | `web.search` + `web.fetch` | Structured travel APIs |
| 5.3 | Flight tracking | `web.fetch` can scrape | No structured flight API |
| 8.2 | Family context awareness | Notes can store manually | No entity/relationship graph |
| 9.1 | Tiered access levels | Per-user trust + PEP | No "named agents" concept |
| 9.2 | Agent-to-agent escalation | PEP confirmation gates | No explicit escalation protocol |
| 10.1 | Morning briefing | Scheduler + delivery | Calendar/email connectors missing |
| 10.2 | Weekly retrospective | Scheduler + `git.log` | Multi-API aggregation missing |
| 11.1 | Newsletter/content drafting | Session memory for style | No proactive generation workflow |
| 15.2 | Price comparison | `web.search` + `web.fetch` | No image recognition, no cart |
| 16.2 | Financial alerts | Scheduler + `web.fetch` | No financial API, no threshold alerting |
| 16.3 | News/keyword monitoring | `web.search` + scheduler | No watchlist, no digest formatting |
| 17.1 | Customer support agent | Channel adapters + sessions | No customer-facing mode, no escalation |
| 17.3 | Personal CRM | Notes/memory for contacts | No CRM model, no outreach |
| 17.4 | Job search automation | `web.search` + scheduler | No tracker, no email connector |
| 18.1 | Language learning | Conversational capability | No curriculum, no proactive nudges |
| 19.1 | Content pipeline (quality gates) | Multi-model routing | No pipeline orchestration |
| 21.1 | Expense tracking / finance queries | `fs.read` for local ledgers | No finance query skill |
| 22.1 | Document filing / OCR | `fs.write` (confirmation-gated) | No OCR, no auto-classification |
| 22.2 | Directory monitoring | Scheduler + `fs.list` | No native file watcher |
| 23.2 | Bookmark/link semantic search | Notes can store links | No embedding search over bookmarks |
| 24.3 | Private document assistant (local RAG) | `fs.read` + local model routing | No chunking/embedding pipeline |
| 25.2 | Household task coordination | Cross-user messaging + reminders | No polling/voting mechanism |

### Planned (Architecture Designed, Not Wired) — 2

| # | Use Case | Design Status |
|---|----------|--------------|
| 8.1 | Learn user preferences over time | Memory hierarchy designed |
| 24.2 | Personal knowledge base / RAG | Memory + embedding architecture designed |

### Missing (Need New Skills/Connectors) — 29

| # | Use Case | Target | Primary Blocker |
|---|----------|--------|----------------|
| 1.3 | Cross-user message relay | v0.5+ | User-facing `message.send` + user routing |
| 2.1 | Email read/summarize | v0.7 | Email connector |
| 2.2 | Email draft/send | v0.7 | Email connector |
| 2.3 | Email bulk actions (unsubscribe, auto-reply) | v0.7 | Email connector |
| 3.1 | Calendar read | v0.7 | Calendar connector |
| 3.2 | Calendar write | v0.7 | Calendar connector |
| 3.3 | Multi-person scheduling | v0.7 | Calendar connector |
| 6.1 | Package tracking | v0.6+ | Email connector + tracking API |
| 7.1 | Music control (Sonos/Spotify) | v0.6+ | Music API skill |
| 7.2 | Smart home (Hue, HomeAssistant) | v0.6+ | HomeAssistant/Hue skill |
| 11.2 | Audio/TTS generation | v0.6+ | TTS API skill |
| 12.1 | Code generation / dev workflows | v0.4 | Proposal-first coding workflow + sandbox/apply contract |
| 12.3 | Autonomous task execution (Kanban) | v0.6+ | Multi-step execution loop |
| 13.1 | Voice/speech input (STT) | v0.7 | Attachment pipeline |
| 13.2 | Voice telephony (outbound calls) | v0.6+ | Twilio + TTS |
| 13.3 | Meeting transcription | v0.7+ | Long-form STT |
| 13.4 | Image recognition/processing | v0.7 | Attachment pipeline |
| 14.1 | Bulk data ingestion | v0.6+ | Ingestion pipeline |
| 15.1 | Grocery/shopping automation | v0.6+ | Vision + commerce APIs |
| 16.1 | Health/fitness dashboard | v0.6+ | Wearable API skills |
| 17.2 | Social media management | v0.6+ | Social media API skills |
| 20.1 | Restaurant check-in / menu logging | v0.6+ | Vision + location APIs |
| 20.2 | Location-aware recall | v0.7+ | Geospatial memory indexing |
| 21.2 | Receipt processing (photo → spreadsheet) | v0.6+ | Vision/OCR |
| 23.1 | Media server management (Plex/Jellyfin) | v0.6+ | Radarr/Sonarr API |
| 24.1 | Voice-to-journal | v0.7+ | STT |
| 25.1 | Family calendar aggregation | v0.7+ | Calendar connectors |
| 26.1 | Browser automation (forms, web admin) | **v0.7** | Playwright sandbox |
| 27.1 | Google Workspace editing | v0.6+ | Google API skills |

---

## References

### Source Articles

- Omar's Lobster article: https://www.omarknows.ai/p/meet-lobster-my-personal-ai-assistant
- Tanay's Complete Guide: https://peerlist.io/tanayvasishtha/articles/clawdbot-the-complete-guide-to-everything-you-can-do-withit (also on [Medium](https://medium.com/towards-explainable-ai/clawdbot-the-complete-guide-to-everything-you-can-do-with-it-b1f37c34fa98))
- 3 weeks as daily driver (Reddit): https://www.reddit.com/r/LocalLLaMA/comments/1r3ro5h/3_weeks_with_openclaw_as_daily_driver_what_worked/
- Popular use cases (Latenode): https://latenode.com/blog/ai/ai-agents/popular-openclaw-use-cases
- Awesome OpenClaw use cases (GitHub): https://github.com/hesamsheikh/awesome-openclaw-usecases
- Every OpenClaw use case (Graham Mann): https://grahammann.net/blog/every-openclaw-use-case
- Master OpenClaw in 30 minutes (Creator Economy): https://creatoreconomy.so/p/master-openclaw-in-30-minutes-full-tutorial
- 25 ways to automate (Hostinger): https://www.hostinger.com/tutorials/openclaw-use-cases

### Related shisad Docs

- Security case studies: `docs/analysis/ANALYSIS-security-casestudies.md`
- Supply-chain analysis: `docs/analysis/ANALYSIS-supply-chain.md`
- Design philosophy: `docs/DESIGN-PHILOSOPHY.md`
- Roadmap: `docs/ROADMAP.md`
