# Resource Market

Pi-Harness keeps classic color themes in the application. Character themes and desktop pets are optional packs.

Open **Settings → Resource Market**. The market reads one catalog:

```text
https://raw.githubusercontent.com/wangmiaozero/pi-Harness-packages/market-index/catalog.json
```

Package names still match:

```text
^@piharness/(theme|pet)-[a-z0-9][a-z0-9-]*$
```

Each package is installed, updated, and removed on its own. The installer downloads that package's GitHub Release ZIP, checks its SHA-256, rejects scripts, symlinks, and path traversal, then commits the files atomically. It does not clone the resource repository.

Theme packs are stored in `<userData>/market/themes/<id>/`. Pet packs use the existing pet installer and are stored in `<userData>/petpacks/<id>/`. The local index is `<userData>/market/index.json`.

The application starts without waiting for the catalog. A saved theme or pet id is not cleared when its files are absent. The workspace uses the base appearance, and Settings says the pack still needs to be installed. Installing that pack restores it. Changing the selection yourself is kept.

Nothing is downloaded automatically. If the catalog cannot be reached, a previously validated catalog can still be shown and packs that are already installed keep working.

## Sponsors

<table>
  <tr>
    <td width="580" align="center" valign="middle">
      <a href="https://infistar.cc/register?aff=S26RFM4B&ref_source=link" style="color:transparent;background-color:transparent;text-decoration:none;border:none;"><img src="../assets/infistar-banner.png" width="560" alt="Pi-Harness × Infistar.cc" style="color:transparent;background-color:transparent;text-decoration:none;border:none;" /></a>
    </td>
    <td valign="middle">
      Pi-Harness × Infistar.cc: Claude, GPT, Gemini, Grok, DeepSeek and more with one key, for a fraction of the official price (up to 99% off, as low as 1% of the official price). 100% official models, each verifiable; thousands of redundant routes with automatic failover; 200+ models from 16 brands with one key.<br>
      Pi-Harness users who register through the <a href="https://infistar.cc/register?aff=S26RFM4B&ref_source=link">dedicated link</a> receive a CNY 5 credit: <a href="https://infistar.cc/register?aff=S26RFM4B&ref_source=link">https://infistar.cc/register?aff=S26RFM4B&ref_source=link</a>
    </td>
  </tr>
  <tr>
    <td width="580" align="center" valign="middle">
      <a href="https://cloud.tencent.com/act/cps/redirect?redirect=6871&amp;cps_key=ece2099a1da90c2f7a4a4c437ad623f8&amp;from=console" style="color:transparent;background-color:transparent;text-decoration:none;border:none;"><img src="../assets/workbuddy-banner.jpg" width="560" alt="Tencent Cloud WorkBuddy" style="color:transparent;background-color:transparent;text-decoration:none;border:none;" /></a>
    </td>
    <td valign="middle">
      [Tencent Cloud] WorkBuddy, an all-scenario AI office workspace. Team flagship edition from CNY 198/month.<br>
      <a href="https://cloud.tencent.com/act/cps/redirect?redirect=6871&amp;cps_key=ece2099a1da90c2f7a4a4c437ad623f8&amp;from=console">https://cloud.tencent.com/act/cps/redirect?redirect=6871&amp;cps_key=ece2099a1da90c2f7a4a4c437ad623f8&amp;from=console</a>
    </td>
  </tr>
</table>

