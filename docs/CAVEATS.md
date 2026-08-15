# What the data does and does not cover

Three things are worth knowing before trusting the panel's output. None of them
are bugs; they are limits of the underlying sources, and the plugin is built to
disclose them rather than paper over them.

## Function signatures are mostly missing, and borrowed ones are labelled

Microsoft generates prototypes on the website from win32metadata rather than
storing them in the markdown, so only 894 of 46,267 sdk-api pages carry a
`## -syntax` block. With those plus malapi.io's 332 and 96 from driver-ddi,
**1,312 of 44,527 APIs have a signature of their own (2.9%)**; following charset
siblings reaches 1,603 (3.6%). Everything else shows parameters and prose but no
prototype.

A borrowed signature is always labelled — *"signature shown is CreateProcessA's"*
— because the ANSI and wide forms genuinely differ (`LPCSTR` against `LPCWSTR`)
even though the parameter order matches.

Closing the rest of the gap means ingesting
[win32metadata](https://github.com/microsoft/win32metadata), which is the source
Microsoft generates those pages from and is MIT licensed, so it can ship inside a
prebuilt index. Reading an installed Windows SDK's headers would also work but
could not be redistributed.

## Capability matching is tiered, and the default tier is the narrow one

capa rules are precise because they pair APIs with constants — `VirtualAlloc`
*and* `number: 0x40` for PAGE_EXECUTE_READWRITE. An import table has APIs and no
constants.

Of 1033 non-library rules, 279 are decided entirely by APIs (`CONFIDENCE_HIGH`)
and 358 also test strings or constants that are invisible to us
(`CONFIDENCE_PARTIAL`). The difference is not academic: on `notepad.exe` the
permissive tier reports 152 capabilities including *bypass UAC* and *disable
Windows Defender*, while the API-only tier reports 19, all accurate.

Even a high-confidence match is an over-approximation. capa's static scope wants
those APIs in the *same function*, whereas an import set only proves they exist
somewhere in the binary. The output says so rather than overclaiming.

## Name folding is aggressive, on purpose

malapi.io lists 122 APIs only under their `A` spelling while modern binaries call
the `W` one. ntdll exports `Nt` and `Zw` at one address. malapi.io title-cases
Winsock (`Socket`) where the real exports are lowercase (`socket`).

Lookup therefore tries exact spellings first and falls back to a case-folded
canonical key. When the entry shown was written against a different spelling, the
panel discloses it — *"MalAPI documents this as CreateProcessA"* — rather than
silently attributing one spelling's write-up to another.
