import { Command } from 'commander';
import { BotaClient } from '../client.js';
import { printTable, printJson, printDetail, ok } from '../output.js';
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
    .option('--end-user <eu_...>', 'Filter by end user ID')
    .option('--device <dev_...>', 'Filter by device ID')
    .option('--status <s>', 'Filter by status')
    .action(async (opts) => {
      const globalOpts = program.opts();
      const client = new BotaClient({ apiKey: getApiKey(), apiUrl: getApiUrl(globalOpts['apiUrl'] as string | undefined) });
      try {
        const res = await client.get<ListResponse>('/v1/recordings', {
          limit: opts.limit,
          end_user_id: opts.endUser,
          device_id: opts.device,
          status: opts.status,
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
      } catch (e) {
        console.error((e as Error).message);
        process.exit(1);
      }
    });

  recordings
    .command('get <id>')
    .description('Get recording by ID')
    .action(async (id: string) => {
      const globalOpts = program.opts();
      const client = new BotaClient({ apiKey: getApiKey(), apiUrl: getApiUrl(globalOpts['apiUrl'] as string | undefined) });
      try {
        const recording = await client.get<Recording>(`/v1/recordings/${id}`);

        const [transcriptionRes] = await Promise.all([
          client.get<TranscriptionListResponse>('/v1/transcriptions', { recording_id: id }).catch(() => ({ data: [] })),
        ]);

        const transcription = transcriptionRes.data[0];
        if (transcription) {
          recording['transcription_status'] = transcription.status;
          recording['transcription_id'] = transcription.id;

          const summaryRes = await client.get<SummaryListResponse>('/v1/summaries', { transcription_id: transcription.id }).catch(() => ({ data: [] }));
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
        console.error((e as Error).message);
        process.exit(1);
      }
    });

  recordings
    .command('transcribe <id>')
    .description('Trigger transcription for a recording')
    .option('--provider <p>', 'ASR provider (whisper, deepgram, assemblyai, elevenlabs)')
    .action(async (id: string, opts) => {
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
        ok(`Transcription ${txn.id} started (status: ${txn.status})`);
      } catch (e) {
        console.error((e as Error).message);
        process.exit(1);
      }
    });

  recordings
    .command('summarize <id>')
    .description('Trigger summary for a recording (looks up transcription automatically)')
    .option('--provider <p>', 'LLM provider (gemini, openai, claude)')
    .option('--template <t>', 'Summary template (general_notes, sales_call, clinical_soap, legal_memo)')
    .action(async (id: string, opts) => {
      const globalOpts = program.opts();
      const client = new BotaClient({ apiKey: getApiKey(), apiUrl: getApiUrl(globalOpts['apiUrl'] as string | undefined) });
      try {
        const txnRes = await client.get<TranscriptionListResponse>('/v1/transcriptions', { recording_id: id });
        const txn = txnRes.data[0];
        if (!txn) {
          console.error('No transcription found for this recording. Run: bota recordings transcribe <id>');
          process.exit(1);
        }
        const summary = await client.post<Summary>('/v1/summaries', {
          transcription_id: txn.id,
          ...(opts.provider && { provider: opts.provider }),
          ...(opts.template && { template: opts.template }),
        });
        if (globalOpts['json']) {
          printJson(summary);
          return;
        }
        ok(`Summary ${summary.id} started (status: ${summary.status})`);
      } catch (e) {
        console.error((e as Error).message);
        process.exit(1);
      }
    });
}
