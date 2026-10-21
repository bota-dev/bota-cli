import { withCommandAuth } from '../invocation-auth.js';
import { Command } from 'commander';
import { BotaClient } from '../client.js';
import { printTable, printJson, printDetail, printPagination, handleCommandFailure, ok } from '../output.js';
import { getApiKey, getApiUrl } from '../config.js';

interface Recording {
  id: string;
  end_user_id: string;
  device_id?: string;
  status: string;
  duration_seconds?: number;
  created_at: string;
  transcription_status?: string;
  summary_status?: string;
  [key: string]: unknown;
}

interface ListResponse {
  data: Recording[];
  has_more?: boolean;
  next_cursor?: string;
}

interface Transcription {
  id: string;
  status: string;
  [key: string]: unknown;
}

interface TranscriptionListResponse {
  data: Transcription[];
}

interface Summary {
  id: string;
  status: string;
  [key: string]: unknown;
}

interface SummaryListResponse {
  data: Summary[];
}

export function registerRecordings(program: Command): void {
  const recordings = program.command('recordings').description('Manage recordings');

  recordings
    .command('list')
    .description('List recordings')
    .option('--limit <n>', 'Max results', '20')
    .option('--cursor <c>', 'Pagination cursor')
    .option('--end-user <eu_...>', 'Filter by end user ID')
    .option('--end-user-id <eu_...>', 'Alias for --end-user')
    .option('--device <dev_...>', 'Filter by device ID')
    .option('--status <s>', 'Filter by status')
    .option('--start-date <iso>', 'Filter created_at at or after this ISO timestamp')
    .option('--end-date <iso>', 'Filter created_at before this ISO timestamp')
    .action(withCommandAuth(program, async (opts) => {
      const globalOpts = program.opts();
      const client = new BotaClient({ apiKey: getApiKey(), apiUrl: getApiUrl(globalOpts['apiUrl'] as string | undefined) });
      try {
        const res = await client.get<ListResponse>('/v1/recordings', {
          limit: opts.limit,
          cursor: opts.cursor,
          end_user_id: opts.endUser ?? opts.endUserId,
          device_id: opts.device,
          status: opts.status,
          start_date: opts.startDate,
          end_date: opts.endDate,
        });
        if (globalOpts['json']) {
          printJson(res);
          return;
        }
        printTable(
          ['id', 'end_user_id', 'status', 'duration_seconds', 'created_at'],
          res.data.map(r => [
            r.id,
            r.end_user_id,
            r.status,
            r.duration_seconds !== undefined ? String(r.duration_seconds) : '',
            r.created_at,
          ]),
        );
        printPagination(res);
      } catch (e) {
        handleCommandFailure(e, Boolean(globalOpts['json']));
      }
    }));

  recordings
    .command('get <id>')
    .description('Get recording by ID')
    .action(withCommandAuth(program, async (id: string) => {
      const globalOpts = program.opts();
      const client = new BotaClient({ apiKey: getApiKey(), apiUrl: getApiUrl(globalOpts['apiUrl'] as string | undefined) });
      try {
        const recording = await client.get<Recording>(`/v1/recordings/${id}`);

        const transcriptionRes = await client.get<TranscriptionListResponse>('/v1/transcriptions', { recording_id: id });

        const transcription = transcriptionRes.data[0];
        if (transcription) {
          recording['transcription_status'] = transcription.status;
          recording['transcription_id'] = transcription.id;

          const summaryRes = await client.get<SummaryListResponse>('/v1/summaries', { transcription_id: transcription.id });
          const summary = summaryRes.data[0];
          if (summary) {
            recording['summary_status'] = summary.status;
            recording['summary_id'] = summary.id;
          }
        }

        if (globalOpts['json']) {
          printJson(recording);
          return;
        }
        printDetail(recording as Record<string, unknown>);
      } catch (e) {
        handleCommandFailure(e, Boolean(globalOpts['json']));
      }
    }));

  recordings
    .command('transcribe <id>')
    .description('Trigger transcription for a recording')
    .option('--provider <p>', 'ASR provider (whisper, deepgram, assemblyai, elevenlabs)')
    .action(withCommandAuth(program, async (id: string, opts) => {
      const globalOpts = program.opts();
      const client = new BotaClient({ apiKey: getApiKey(), apiUrl: getApiUrl(globalOpts['apiUrl'] as string | undefined) });
      try {
        const txn = await client.post<Transcription>('/v1/transcriptions', {
          recording_id: id,
          ...(opts.provider && { provider: opts.provider }),
        });
        if (globalOpts['json']) {
          printJson(txn);
          return;
        }
        ok(`Transcription ${txn.id} requested (status: ${txn.status})`);
      } catch (e) {
        handleCommandFailure(e, Boolean(globalOpts['json']));
      }
    }));

  recordings
    .command('summarize <id>')
    .description('Trigger summary for a recording (looks up transcription automatically)')
    .option('--provider <p>', 'LLM provider (gemini, openai, claude)')
    .option('--template <id>', 'Template ID or built-in alias (general_notes, sales_call, clinical_soap, legal_memo)')
    .option('--prompt <text>', 'Custom summary prompt (10–10000 characters; alternative to --template)')
    .action(withCommandAuth(program, async (id: string, opts) => {
      if (Boolean(opts.template) === Boolean(opts.prompt)) {
        throw new Error('Provide exactly one of --template or --prompt');
      }
      if (opts.prompt && (opts.prompt.length < 10 || opts.prompt.length > 10000)) {
        throw new Error('--prompt must contain 10–10000 characters');
      }
      const globalOpts = program.opts();
      const client = new BotaClient({ apiKey: getApiKey(), apiUrl: getApiUrl(globalOpts['apiUrl'] as string | undefined) });
      try {
        const txnRes = await client.get<TranscriptionListResponse>('/v1/transcriptions', { recording_id: id });
        const txn = txnRes.data[0];
        if (!txn) {
          throw new Error('No transcription found for this recording. Run: bota recordings transcribe <id>');
        }
        const summary = await client.post<Summary>('/v1/summaries', {
          transcription_id: txn.id,
          ...(opts.provider && { provider: opts.provider }),
          ...(opts.template && { template_id: ['general_notes', 'sales_call', 'clinical_soap', 'legal_memo'].includes(opts.template) ? `tmpl_${opts.template}` : opts.template }),
          ...(opts.prompt && { prompt: opts.prompt }),
        });
        if (globalOpts['json']) {
          printJson(summary);
          return;
        }
        ok(`Summary ${summary.id} requested (status: ${summary.status})`);
      } catch (e) {
        handleCommandFailure(e, Boolean(globalOpts['json']));
      }
    }));
}
