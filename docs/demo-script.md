# VulnCouncil — recording and judging script

## Prepare before recording

1. Open Docker Desktop and Ollama. If the Ollama server is stopped, run `ollama serve` in a separate terminal.
2. Start the model-assisted stack:

```sh
cd Vulncouncil
ollama pull qwen3:4b
make model
```

3. Open **http://localhost:8000** and refresh to load the minimalist dashboard.
4. Select **Live repo auditor**, choose **This workspace**, and enable model-assisted reviews. Confirm SLIM transport and model reasoning in the audit's labels.
5. Keep a completed workspace audit available in audit history. Live requests need internet access and local inference takes time. Identify a saved result by its capture time; do not present it as a newly completed live run.
6. Record the browser window with readable text. Close unrelated tabs and notifications.

## The idea in one sentence

**VulnCouncil gives developers three AI reviewers who check known security warnings in the software their project depends on, compare their conclusions, and explain what to investigate next.**

## Three-minute recording

Read the quoted lines aloud. The on-screen notes are directions for you.

### 0:00–0:30 — The problem

**On screen:** Open Live repo auditor, choose This workspace, enable model-assisted reviews, and start the audit.

**Say:**

> Most applications depend on hundreds of software components. When one has a security warning, a developer has to ask: does it affect our version, what does it mean for our application, and what should we do next?
>
> VulnCouncil helps answer those questions. Let's use it on the project we're presenting today.

### 0:30–1:10 — Three reviewers, three questions

**On screen:** Show the audit progressing. Point to the three reviewer roles as they appear.

**Say:**

> The first reviewer looks for known security issues. The second checks whether the warning applies to the version our project uses. The third looks at possible fixes and what still needs checking.
>
> They compare their conclusions and challenge claims that the evidence doesn't support. You can see their reasoning and open the sources behind it.

**If the audit is still running:** Select a completed workspace audit in history and say:

> While the new check runs, here's a previously completed check of this same project. Its capture time is shown here.

### 1:10–1:55 — A real result

**On screen:** Open the NLTK 3.10.3 finding in the saved workspace audit. Show its public security notice. If the new run returns different results, describe what it actually displays.

**Say:**

> Our recorded check examined 302 software component versions and found a public security warning affecting a component called NLTK. This is a real component listed in our own project.
>
> The important distinction is that an affected component doesn't automatically mean someone can break into our application. We still need to check whether we use the affected features. VulnCouncil keeps that question visible and gives us a next step to investigate.

### 1:55–2:35 — Make the decision understandable

**On screen:** Show the three reviewer positions and expand their review history. Open the source details briefly.

**Say:**

> Here, you can read what each reviewer concludes and why. If they disagree, that disagreement stays visible. A developer can follow the evidence instead of relying on one confident answer.
>
> For this finding, the next step is to check how our application uses the component and review the available fixes. The report keeps that separate from claiming the application has been attacked or that an upgrade is guaranteed to work.

Only describe a reviewer changing its mind if the displayed review history shows that change. Keep the raw agent-card JSON out of the main recording; it describes an agent rather than showing its work.

### 2:35–3:00 — The takeaway

**On screen:** Show what was checked and anything skipped. Export the report.

**Say:**

> The result is a review a developer can inspect: what was checked, what was found, what remains uncertain, and what to investigate next.
>
> VulnCouncil helps teams turn security warnings into decisions they can explain and act on.

## Optional example: checking a proposed upgrade

**On screen:** Select the saved Apache Airflow audit. Explain that it checks an older published dependency list, not today's Airflow release. Show the Authlib candidate-version result.

**Say:**

> We also checked an older dependency list from a real open-source project. In this recorded result, a published upgrade candidate still had security warnings. The system kept those warnings visible rather than calling the upgrade safe. The team would still need to check the remaining issues and test the upgrade.

## Plain-language answers for judges

**Why three reviewers?**

> Finding a warning, checking whether it applies, and evaluating a fix are different jobs. We give each reviewer a different responsibility and let them question each other's conclusions. We still need a broader comparison to measure whether that improves decisions over a single reviewer.

**How is this different from a regular security scanner?**

> A scanner finds known issues. Our focus is the review that follows: explaining what the evidence supports, what remains uncertain, and what the developer should investigate next.

**Does it fix the project automatically?**

> No. It runs the checks and reviews automatically, then leaves changes and testing to the developer.

**Does it guarantee the application is secure?**

> No. It checks known issues within the files and versions it can read. It shows what it couldn't check and doesn't treat an empty result as a security guarantee.

**Does it use real data?**

> Yes. This demo reads actual project dependency files and checks public security records. Findings link to those records. Saved results are labeled as earlier checks.

**What have you tested?**

> The implementation passed 89 tests, two real repository audits, and desktop and mobile browser checks. That shows the workflow runs; it doesn't prove it finds every security issue.

**How do the reviewers communicate?**

> They run as separate workers and exchange review messages through SLIM. The report records those exchanges so we can show they happened.

## Supporting files

- [Executed workspace case](real-audit-case.md)
- [Workflow and limits](live-repository-audit.md)
- [Actual public-API acceptance report](repository-audit-verification.json)

The synthetic evaluation and billing lab test the original deliberation protocol. They are separate from real repository audit accuracy.
