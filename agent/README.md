# Agent

`agent-polling.ps1` runs on (or with network access to) a Domain Controller. It polls
the backend over HTTP(S), executes the requested change on Active Directory, and
reports the result. It only makes **outbound** requests — no inbound port is opened.

## Setup

1. Copy `agent-polling.ps1` and `config.example.json` to the server, e.g. `C:\AD-Automation\`.
2. Rename `config.example.json` to `config.json` and fill it in:

   | Key | Meaning |
   |---|---|
   | `backend_url` | Where the backend is reachable from the DC |
   | `api_key` | Returned **once** by `POST /api/agents/register` |
   | `domain` | UPN suffix, e.g. `company.local` |
   | `departments` | Department → OU distinguished name + security group |

   The department names must match the ones in the web UI's dropdown.
3. Run it (PowerShell 5.1, ActiveDirectory module installed):

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\agent-polling.ps1
   ```

   To keep it running after reboot, register it as a Scheduled Task (at startup,
   running as the service account).

`config.json` and `log.txt` are in `.gitignore` — never commit them.

## What it does

Every 10 seconds: `GET /api/pending` (header `X-API-Key`), then for each request:

| `action` | AD commands |
|---|---|
| `onboard` | `New-ADUser` (must change password at next logon) + `Add-ADGroupMember` |
| `offboard` | `Remove-ADGroupMember` (all groups) + `Disable-ADAccount` — never deletes |
| `reactivate` | `Enable-ADAccount` + add back to the department group (matched by OU) |

The outcome goes to `POST /api/result/{id}` as `{"status": "done"|"failed", "username": "...", "error": "..."}`.
Bulk creation needs no special handling — the UI queues one `onboard` request per employee.

## Security notes

- Run the agent under a dedicated service account with **delegated** rights on the
  employees' OUs only (create/disable/enable users, manage group membership) — not Domain Admin.
- The backend hands the agent the temporary password in plain text so it can create the
  account, so put the backend behind **HTTPS** in any real deployment.
