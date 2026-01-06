On December 3rd, 2025, the React team disclosed CVE-2025-55182, dubbed React2Shell, a critical Remote Code Execution (RCE) vulnerability affecting React Server Components (RSC).
With a CVSS score of 10.0 and an exploitation rate close to 100% on default configurations, this flaw represents a severe threat to modern infrastructures relying on React 19 and Next.js.

The open-source security ecosystem reacted swiftly. Within hours of the disclosure, CrowdSec released a dedicated virtual patching detection rule, once again demonstrating how collaborative defense can drastically reduce exposure time.
&nbsp;

---

&nbsp;
### Technical Analysis of React2Shell

#### Vulnerability Overview
**CVE-2025-55182** is caused by **unsafe deserialization** in the *Flight protocol* used by React Server Components.
The server-side code processes HTTP payloads **without sufficient validation**, allowing attackers to inject crafted objects that result in **arbitrary code execution**.

**Affected packages** (versions 19.0.0 → 19.2.0):
- `react-server-dom-webpack`
- `react-server-dom-turbopack`
- `react-server-dom-parcel`

**Impacted frameworks**:
- Next.js 15.0.4 → 16.0.6 (including canaries 14.3.0-canary.77+)
- React Router (RSC mode)
- Waku, Vite RSC, Parcel RSC
- RedwoodSDK

**⚠️ Critical point**:
**A freshly created Next.js application using `create-next-app` is vulnerable by default**.
No special configuration is required, simply enabling Server Components is enough.

#### Scénario d'attaque
An attacker can:
- Send a malicious HTTP POST request to any endpoint
- Abuse the vulnerable deserialization logic
- Execute arbitrary server-side code
- Gain full server access
- Exfiltrate data, deploy backdoors, and pivot laterally within the infrastructure
&nbsp;

---

&nbsp;
### CrowdSec’s Response to React2Shell

#### A Fast, Community-Driven Reaction
One of the major strengths of open-source security is its reaction speed.
Just **hours after public disclosure**, CrowdSec released a dedicated detection rule: `vpatch-CVE-2025-55182`

#### How the Detection Rule Works
The `vpatch-CVE-2025-55182` rule focuses on **identifying real-world exploitation attempts** of React2Shell by correlating multiple strong signals, significantly reducing false positives:
- **HTTP POST method** -> Exploitation relies on server-side form submissions.
- **Presence of React Server Action headers (`next-action`, `rsc-action-id`)** -> strong indicators of RSC/Next.js flows.
- **Tampering with internal Flight parameters (`status`, `resolved_model`)** -> sensitive fields involved in the vulnerable deserialization logic.
- **Suspicious `$@` payload pattern** -> Known signature associated with React2Shell injection techniques.

By correlating these indicators, CrowdSec detects exploitation attempts **even in the absence of a publicly available working exploit**, making this rule an effective **preventive virtual patch**.

#### Installing the CrowdSec Virtual Patch
If you already run CrowdSec with the **AppSec (WAF) component**, enabling protection against React2Shell is straightforward:
```bash
cscli appsec-rules install crowdsecurity/vpatch-CVE-2025-55182
```
Within seconds, the AppSec engine begins detecting and mitigating exploitation attempts targeting **CVE-2025-55182**.

#### Adding the React2Shell CrowdSec Blocklist
In addition to application-layer detection, CrowdSec also provides a **dedicated React2Shell IP blocklist**, built from real-world exploitation attempts observed across the community.
This blocklist aggregates **source IPs actively exploiting CVE-2025-55182** and allows defenders to **block attackers at the network or firewall level**, before requests even reach the application.

**Benefits of using the blocklist**:
- Blocks known React2Shell attackers globally
- Reduces load on the application and WAF
- Complements AppSec virtual patching with network-level enforcement
- Automatically updated through CrowdSec’s threat intelligence

The React2Shell blocklist is available here:
👉 https://app.crowdsec.net/blocklists/6936fb6f5f136d434bcbd4af

#### Important: Patch Your Dependencies
While CrowdSec provides **immediate protection**, virtual patching does not replace vendor fixes.

To fully remediate React2Shell, ensure you update:
- **React 19.x** -> patched release
- **Next.js** -> official security release published by Vercel

Applying these updates removes the vulnerability at its source and should be done **even if CrowdSec is already deployed**.
&nbsp;

---

&nbsp;
### Conclusion

**CVE-2025-55182 (React2Shell)** is a maximum-severity vulnerability with widespread impact across the modern React ecosystem.
However, it also highlights the effectiveness of **collaborative open-source security*.

👉 **CrowdSec delivered a detection rule within hours**, enabling organizations to defend themselves immediately through virtual patching.

**Recommended actions for all organizations using React Server Components:**
1. Apply official patches as soon as possible
2. Deploy CrowdSec AppSec with the virtual patching collections
3. Monitor exploitation attempts targeting RSC endpoints
4. Continuously test detection and response (Purple Team approach)

React2Shell is a clear reminder that fast detection, shared intelligence, and community-driven defense are essential to securing modern web stacks.

---

### Additional Resources
- [Detecting React2Shell: The maximum-severity RCE Vulnerability affecting React Server Components and Next.js](https://www.sysdig.com/blog/detecting-react2shell)
- [Security Advisory: CVE-2025-66478](https://nextjs.org/blog/CVE-2025-66478)
- [React2Shell (CVE-2025-55182)](https://react2shell.com/)
