# Khmer review: Angket Bot file-scan messages

**Who this is for:** a native Khmer speaker. About 10 minutes. No technical background needed.

Angket Bot is a Telegram bot that tells people whether a message, link or file looks like a scam. These 16 lines appear in its replies when it inspects a file. The Khmer was written by an AI as a first draft and has never been read by a native speaker.

## What I need from you

For each row: is the Khmer **correct, natural, and says the same as the English?** Reply with the row number and either `OK` or your corrected Khmer. Please keep anything in `{curly braces}` exactly as written: the bot fills those in.

## The one rule that matters most

The bot must **never claim certainty it does not have.** Rows 3, 5 and 6 say a file *could not be checked*. If any Khmer wording could make a reader think the file is *confirmed safe* or *confirmed a virus*, please fix it.

## Messages

| # | When the user sees it | English | Khmer (first draft) | Check |
|---|---|---|---|---|
| 1 | A file was over 20 MB and could not be checked at all. | This file is too large for Angket to scan (over 20 MB), so it could not be checked at all. | ឯកសារនេះធំពេកសម្រាប់ Angket ស្កេន (លើសពី 20 MB) ដូច្នេះមិនអាចត្រួតពិនិត្យបានទាល់តែសោះ។ | Plain, calm. Says it was NOT checked, not that it is dangerous. |
| 2 | A file could not be downloaded for scanning. | This file could not be checked right now because of a temporary problem, so there is no result for it. | ឯកសារនេះមិនអាចត្រួតពិនិត្យបានក្នុងពេលនេះដោយសារបញ្ហាបណ្តោះអាសន្ន ដូច្នេះមិនមានលទ្ធផលសម្រាប់វាទេ។ | Same: 'could not be checked', not 'dangerous'. |
| 3 | THE KEY ONE. Shown for a file that could not be checked AND has a disguised name (e.g. report.xlsx.z). | Two warning signs together: Angket could not check this file at all, and its name is disguised. Treat it as unsafe until it has been verified. | សញ្ញាព្រមានពីរបូកគ្នា៖ Angket មិនអាចពិនិត្យឯកសារនេះបានទាល់តែសោះ ហើយឈ្មោះរបស់វាត្រូវបានបំបាំងកាយ។ សូមចាត់ទុកថាវាមិនមានសុវត្ថិភាព រហូតដល់វាត្រូវបានផ្ទៀងផ្ទាត់។ | Must read as 'we could not check it + disguised name = treat as unsafe until verified'. It must NOT say 'this is a virus/malware' as a fact. |
| 4 | The verdict was raised to Scam because of the file itself. | Overridden: the attached file shows strong warning signs of its own, regardless of the message text. | ត្រូវបានកែតម្រូវ៖ ឯកសារភ្ជាប់បង្ហាញសញ្ញាព្រមានខ្លាំងដោយខ្លួនវាផ្ទាល់ ដោយមិនគិតពីអត្ថបទក្នុងសារ។ | 'Strong warning signs of its own'. Must not say any antivirus confirmed it. |
| 5 | No antivirus check happened, and nothing odd in the name or structure. | Nothing suspicious was found in its name or structure either — but that is not the same as an antivirus check, so it can't be confirmed safe. | ក៏រកមិនឃើញអ្វីគួរឱ្យសង្ស័យនៅក្នុងឈ្មោះ ឬរចនាសម្ព័ន្ធរបស់វាដែរ — ប៉ុន្តែនោះមិនមែនជាការស្កេនកំចាត់មេរោគទេ ដូច្នេះមិនអាចបញ្ជាក់ថាវាមានសុវត្ថិភាពបានទេ។ | Must NOT sound like 'it is safe'. It says it still cannot be confirmed safe. |
| 6 | A message has an attachment no antivirus could check. | The attached file could not be verified by any antivirus engine, so this message can't be confirmed safe. | ឯកសារភ្ជាប់មិនអាចត្រូវបានផ្ទៀងផ្ទាត់ដោយម៉ាស៊ីនកំចាត់មេរោគណាមួយបានទេ ដូច្នេះមិនអាចបញ្ជាក់ថាសារនេះមានសុវត្ថិភាពបានទេ។ | Same: 'cannot be confirmed safe'. |
| 7 | A file named '.pdf' (etc.) is really a program. | The file is named '.{claimed_ext}' but its contents are actually a {real_type} program. | ឯកសារនេះមានឈ្មោះជា '.{claimed_ext}' ប៉ុន្តែមាតិការបស់វាពិតជាកម្មវិធីប្រភេទ {real_type}។ | Keep {claimed_ext} and {real_type} placeholders exactly as they are. |
| 8 | A file named '.pdf' (etc.) is really a ZIP/RAR archive. | The file is named '.{claimed_ext}' but it is actually a {real_type} archive. | ឯកសារនេះមានឈ្មោះជា '.{claimed_ext}' ប៉ុន្តែវាពិតជាឯកសារបង្ហាប់ប្រភេទ {real_type}។ | Keep {claimed_ext} and {real_type}. |
| 9 | The file name uses a hidden character to fake its extension. | The file name uses a hidden right-to-left control character to fake its extension — a deliberate disguise. | ឈ្មោះឯកសារប្រើតួអក្សរបញ្ជាលាក់ (ពីស្តាំទៅឆ្វេង) ដើម្បីក្លែងកន្ទុយឈ្មោះ — ជាការបំបាំងកាយដោយចេតនា។ | Explain in plain words; no jargon. |
| 10 | An archive contains a program or script. | The archive contains a program or script: '{entry}'. | ឯកសារបង្ហាប់នេះមានកម្មវិធី ឬស្គ្រីបនៅខាងក្នុង៖ '{entry}'។ | Keep {entry}. |
| 11 | An archive contains a disguised program. | The archive contains a disguised program: '{entry}'. | ឯកសារបង្ហាប់នេះមានកម្មវិធីដែលបំបាំងកាយនៅខាងក្នុង៖ '{entry}'។ | Keep {entry}. |
| 12 | An archive is password-protected, so it could not be checked. | The archive is password-protected, so its contents can't be checked — a common way to slip malware past scanners. | ឯកសារបង្ហាប់នេះត្រូវបានការពារដោយពាក្យសម្ងាត់ ដូច្នេះមិនអាចពិនិត្យមាតិការបស់វាបានទេ — ជាវិធីសាមញ្ញមួយដើម្បីបញ្ជូនមេរោគឱ្យគេចពីការស្កេន។ | Plain wording for 'password-protected'. |
| 13 | An archive has more than 2000 files, so only the first 2000 were checked. | The archive holds more than {count} files, so only the first {count} could be checked. | ឯកសារបង្ហាប់នេះមានឯកសារច្រើនជាង {count} ដូច្នេះអាចពិនិត្យបានតែ {count} ដំបូងប៉ុណ្ណោះ។ | Keep {count} twice. |
| 14 | A Word/Excel file contains macros. | This Office document contains macros, which can run code when it is opened. | ឯកសារ Office នេះមានម៉ាក្រូ (macro) ដែលអាចដំណើរការកូដនៅពេលបើកវា។ | Is 'macro' understood by ordinary users? Suggest a clearer word if not. |
| 15 | A PDF tells the reader to start another program. | This PDF contains an instruction to launch another program. | ឯកសារ PDF នេះមានពាក្យបញ្ជាសម្រាប់បើកដំណើរការកម្មវិធីផ្សេង។ | Plain wording. |
| 16 | A PDF contains JavaScript. | This PDF contains embedded JavaScript. | ឯកសារ PDF នេះមាន JavaScript បង្កប់នៅខាងក្នុង។ | Is the term OK, or should it say 'script'? |

## Technical keys (for the developer, not the reviewer)

1. `reason_file_too_large`  -> `bot/response/translate/km.py`
2. `reason_file_scan_failed`  -> `bot/response/translate/km.py`
3. `reason_file_unscannable_disguised`  -> `bot/response/translate/km.py`
4. `reason_override_file_local`  -> `bot/response/translate/km.py`
5. `reason_file_no_local_findings`  -> `bot/response/translate/km.py`
6. `reason_file_unverified_attachment`  -> `bot/response/translate/km.py`
7. `content_disguised_executable`  -> `bot/response/translate/km.py`
8. `content_disguised_archive`  -> `bot/response/translate/km.py`
9. `content_rtlo_filename`  -> `bot/response/translate/km.py`
10. `content_archive_executable`  -> `bot/response/translate/km.py`
11. `content_archive_disguised_entry`  -> `bot/response/translate/km.py`
12. `content_archive_encrypted`  -> `bot/response/translate/km.py`
13. `content_archive_too_many_entries`  -> `bot/response/translate/km.py`
14. `content_office_macros`  -> `bot/response/translate/km.py`
15. `content_pdf_launch`  -> `bot/response/translate/km.py`
16. `content_pdf_javascript`  -> `bot/response/translate/km.py`
