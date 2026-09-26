# Code signing lsnet.exe

Status: **not set up yet.** Releases ship an unsigned `lsnet.exe`. This page covers what signing would get us, the options, and the setup steps for the one we'd pick.

Researched September 2026. Prices, eligibility and names in this area change often, so check the sources at the end before acting.

## What signing does and doesn't do

A signature proves `lsnet.exe` came from us and hasn't been tampered with. Windows shows our name as the publisher, and companies that block unsigned programs will allow it.

It does **not** stop SmartScreen warnings straight away. Since 2024, even EV certificates no longer bypass SmartScreen. Every new signer builds a reputation over several releases signed with the same identity, and warnings fade as it grows.

Warnings matter less for a command-line tool than for an app. SmartScreen mostly checks programs opened from File Explorer after a browser download, not programs run from a terminal. We haven't confirmed this with lsnet itself.

## The options

| | Azure Artifact Signing | SignPath Foundation | OV certificate from a CA |
|---|---|---|---|
| Cost | $9.99/month (up to 5,000 signatures) | Free for open source | $150–300/year |
| Publisher shown | **Our name** | "SignPath Foundation" | Our name |
| Who can use it | Individuals in the **US or Canada only**; organizations also in the EU and UK | Approved open-source projects | Anyone |
| Build requirement | None: sign anywhere, including the Windows release box | Every job before signing must run on **GitHub-hosted** runners | Key on a USB token or cloud HSM (required since June 2023) |
| Setup time | A few business days for ID checks | Manual review, 1–2 weeks | Several days, plus shipping a token |

Azure Artifact Signing was called Trusted Signing until early 2026. Microsoft recommends it for software distributed outside the Microsoft Store.

## Recommendation: Azure Artifact Signing

If we're signing as an individual in the US or Canada, use Azure Artifact Signing:

- It's the cheapest option that shows our own name as the publisher.
- It fits the current release process. The Windows exe is already built from the tag on the Windows box (see [RELEASING.md](../RELEASING.md)), and signing would slot in right before zipping, with no hardware token.

SignPath is free, but it has three drawbacks for lsnet:

- The publisher would be "SignPath Foundation", not us.
- The Windows build would have to move off our self-hosted runner and onto GitHub's hosted runners.
- Its terms bar software "designed to identify or exploit security vulnerabilities". lsnet isn't that, but a reviewer might question a network scanner.

An OV certificate is the fallback if Azure's eligibility rules rule us out and SignPath doesn't fit.

## Setting up Azure Artifact Signing

### In the Azure portal (one time)

1. **Get a paid Azure subscription.** Pay-as-you-go works; free, trial and sponsored subscriptions don't. For individual validation, the billing account must be of type **Individual**, with the legal name and address exactly as they appear on the government ID used in step 3.
2. **Create an Artifact Signing account.** Make a resource group, then an Artifact Signing account (Basic tier) in a nearby region.
3. **Verify identity.** Give yourself the identity verifier role on the account, then submit a **Public Trust** identity validation with your government ID. This is the step that takes a few business days.
4. **Create a certificate profile.** Once validated, create a Public Trust certificate profile.
5. **Allow signing.** Give the account that will sign the certificate profile signer role.

Role and tool names may have changed with the rename from Trusted Signing. Use the quickstart linked below for the current ones.

### On the Windows release box (one time)

6. **Install the tools.** `signtool` already comes with the Windows SDK installed with the Visual Studio Build Tools. Add Azure's Artifact Signing client tools (which provide the signing plugin, a `.dll` that `signtool` loads) and the Azure CLI, then sign in once with `az login`.

### Each release

7. **Sign, then verify.** Between building `lsnet.exe` and zipping it:

   ```powershell
   signtool sign /v /fd SHA256 /tr http://timestamp.acs.microsoft.com /td SHA256 `
     /dlib <path to the Artifact Signing .dll> /dmdf metadata.json target\release\lsnet.exe
   signtool verify /pa /v target\release\lsnet.exe
   ```

   `metadata.json` names the endpoint for the account's region, the account and the certificate profile:

   ```json
   {
     "Endpoint": "https://<region>.codesigning.azure.net",
     "CodeSigningAccountName": "<account>",
     "CertificateProfileName": "<profile>"
   }
   ```

   The timestamp (`/tr`) is essential. Azure's certificates are valid for only about 3 days, and the timestamp is what keeps a signature valid after its certificate expires.

8. **Update RELEASING.md.** Once this works, add the signing step to the Windows binary section and the checklist.

Signing could later move into CI using GitHub's OIDC sign-in to Azure, so no secret is stored in the repo. Signing by hand at release time is simpler to start with.

## Sources

- [Code signing options for Windows app developers](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options) (Microsoft Learn)
- [Azure Artifact Signing pricing](https://azure.microsoft.com/en-us/pricing/details/artifact-signing/)
- [Artifact Signing quickstart](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart) and [FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq)
- [Code signing Windows apps may be easier with new Azure Artifact service](https://www.devclass.com/security/2026/01/14/code-signing-windows-apps-may-be-easier-and-more-secure-with-new-azure-artifact-service/4079554) (DevClass)
- [SignPath: GitHub as a trusted build system](https://docs.signpath.io/trusted-build-systems/github)
- [SignPath Foundation conditions for open-source projects](https://signpath.org/terms.html)
