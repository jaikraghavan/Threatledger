"""Build the non-NIST framework seed files in data/frameworks/.

Run:  uv run python scripts/seeds/build_seeds.py

Content policy (PLAN.md Q1):
- ISO/IEC 27001, AICPA SOC 2 TSC and CIS Controls v8 are copyrighted / licence-restricted:
  identifiers and short descriptive (paraphrased) titles only.
- HIPAA Security Rule and India's DPDP Act are public law: official section headings with
  plain-language summaries (not verbatim legal text). Link users to the official text.
All seeded content is INDICATIVE: verify against the official text.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import write

INDICATIVE = "# Seeded by ThreatLedger. INDICATIVE: verify against the official text.\n"


# ----------------------------------------------------------------------------- ISO 27001:2022
def iso() -> None:
    themes = {
        "A.5": (
            "Organizational controls",
            [
                "Information security policies",
                "Information security roles and responsibilities",
                "Segregation of duties",
                "Management responsibilities",
                "Contact with authorities",
                "Contact with special interest groups",
                "Threat intelligence",
                "Information security in project management",
                "Inventory of information and associated assets",
                "Acceptable use of information and associated assets",
                "Return of assets",
                "Classification of information",
                "Labelling of information",
                "Information transfer",
                "Access control",
                "Identity management",
                "Authentication information",
                "Access rights",
                "Information security in supplier relationships",
                "Information security in supplier agreements",
                "Information security in the ICT supply chain",
                "Monitoring, review and change management of supplier services",
                "Information security for use of cloud services",
                "Incident management planning and preparation",
                "Assessment and decision on security events",
                "Response to information security incidents",
                "Learning from information security incidents",
                "Collection of evidence",
                "Information security during disruption",
                "ICT readiness for business continuity",
                "Legal, statutory, regulatory and contractual requirements",
                "Intellectual property rights",
                "Protection of records",
                "Privacy and protection of personal data (PII)",
                "Independent review of information security",
                "Compliance with security policies, rules and standards",
                "Documented operating procedures",
            ],
        ),
        "A.6": (
            "People controls",
            [
                "Screening",
                "Terms and conditions of employment",
                "Security awareness, education and training",
                "Disciplinary process",
                "Responsibilities after termination or change of employment",
                "Confidentiality or non-disclosure agreements",
                "Remote working",
                "Information security event reporting",
            ],
        ),
        "A.7": (
            "Physical controls",
            [
                "Physical security perimeters",
                "Physical entry",
                "Securing offices, rooms and facilities",
                "Physical security monitoring",
                "Protection against physical and environmental threats",
                "Working in secure areas",
                "Clear desk and clear screen",
                "Equipment siting and protection",
                "Security of assets off-premises",
                "Storage media",
                "Supporting utilities",
                "Cabling security",
                "Equipment maintenance",
                "Secure disposal or re-use of equipment",
            ],
        ),
        "A.8": (
            "Technological controls",
            [
                "User endpoint devices",
                "Privileged access rights",
                "Information access restriction",
                "Access to source code",
                "Secure authentication",
                "Capacity management",
                "Protection against malware",
                "Management of technical vulnerabilities",
                "Configuration management",
                "Information deletion",
                "Data masking",
                "Data leakage prevention",
                "Information backup",
                "Redundancy of information processing facilities",
                "Logging",
                "Monitoring activities",
                "Clock synchronisation",
                "Use of privileged utility programs",
                "Installation of software on operational systems",
                "Network security",
                "Security of network services",
                "Segregation of networks",
                "Web filtering",
                "Use of cryptography",
                "Secure development life cycle",
                "Application security requirements",
                "Secure system architecture and engineering principles",
                "Secure coding",
                "Security testing in development and acceptance",
                "Outsourced development",
                "Separation of development, test and production environments",
                "Change management",
                "Test information",
                "Protection of information systems during audit testing",
            ],
        ),
    }
    assert [len(v[1]) for v in themes.values()] == [37, 8, 14, 34]
    reqs = []
    for dom, (title, items) in themes.items():
        reqs.append({"ref": dom, "title": title, "is_domain": True})
        reqs += [{"ref": f"{dom}.{i}", "title": t, "parent": dom} for i, t in enumerate(items, 1)]
    write(
        "iso-27001-2022.yaml",
        INDICATIVE,
        {
            "code": "ISO27001-2022",
            "name": "ISO/IEC 27001:2022 Annex A",
            "version": "2022",
            "publisher": "ISO/IEC",
            "source_url": "https://www.iso.org/standard/27001",
            "licence_note": "Copyrighted standard: identifiers and short descriptive titles only. "
            "Import the official text from your licensed copy.",
            "content_level": "reference",
            "description": "The 93 Annex A information security controls in four themes.",
        },
        reqs,
    )


# ----------------------------------------------------------------------------- SOC 2 TSC
def soc2() -> None:
    groups = [
        (
            "CC1",
            "Control environment",
            [
                "Commitment to integrity and ethical values",
                "Board independence and oversight of internal control",
                "Structures, reporting lines, authorities and responsibilities",
                "Attracting, developing and retaining competent people",
                "Accountability for internal control responsibilities",
            ],
        ),
        (
            "CC2",
            "Communication and information",
            [
                "Relevant, quality information supports internal control",
                "Internal communication of objectives and responsibilities",
                "Communication with external parties",
            ],
        ),
        (
            "CC3",
            "Risk assessment",
            [
                "Objectives specified clearly enough to identify risks",
                "Identification and analysis of risks",
                "Consideration of fraud risk",
                "Identification of significant changes",
            ],
        ),
        (
            "CC4",
            "Monitoring activities",
            [
                "Ongoing and/or separate evaluations of controls",
                "Timely communication of control deficiencies",
            ],
        ),
        (
            "CC5",
            "Control activities",
            [
                "Control activities selected to mitigate risks",
                "General controls over technology",
                "Control activities deployed through policies and procedures",
            ],
        ),
        (
            "CC6",
            "Logical and physical access controls",
            [
                "Logical access security over protected information assets",
                "Registration and authorisation before access is granted",
                "Role-based access, least privilege and segregation of duties",
                "Physical access restrictions",
                "Protection and disposal of assets no longer needed",
                "Protection against threats from outside system boundaries",
                "Protection of information in transmission and movement",
                "Prevention and detection of unauthorised or malicious software",
            ],
        ),
        (
            "CC7",
            "System operations",
            [
                "Detection of configuration changes and vulnerabilities",
                "Monitoring of system components for anomalies",
                "Evaluation of security events to identify incidents",
                "Incident response",
                "Recovery from security incidents",
            ],
        ),
        ("CC8", "Change management", ["Authorised, tested and approved changes"]),
        (
            "CC9",
            "Risk mitigation",
            [
                "Mitigation of business disruption risk",
                "Vendor and business partner risk management",
            ],
        ),
        (
            "A1",
            "Availability",
            [
                "Capacity management",
                "Environmental protection, backup and recovery infrastructure",
                "Recovery plan testing",
            ],
        ),
        (
            "C1",
            "Confidentiality",
            [
                "Identification and protection of confidential information",
                "Disposal of confidential information",
            ],
        ),
        (
            "PI1",
            "Processing integrity",
            [
                "Definitions of data and processing specifications",
                "Complete and accurate inputs",
                "Processing meets specifications",
                "Complete, accurate and timely outputs",
                "Storage of inputs, in-process items and outputs",
            ],
        ),
    ]
    privacy = [
        ("P1.1", "Privacy notice"),
        ("P2.1", "Choice and consent"),
        ("P3.1", "Collection limited to identified purposes"),
        ("P3.2", "Explicit consent for collection where required"),
        ("P4.1", "Use limited to identified purposes"),
        ("P4.2", "Retention of personal information"),
        ("P4.3", "Secure disposal of personal information"),
        ("P5.1", "Data subject access"),
        ("P5.2", "Correction of personal information"),
        ("P6.1", "Disclosure to third parties with consent"),
        ("P6.2", "Record of authorised disclosures"),
        ("P6.3", "Record of unauthorised disclosures"),
        ("P6.4", "Third-party privacy commitments"),
        ("P6.5", "Third-party notification of unauthorised disclosures"),
        ("P6.6", "Breach notification to data subjects and others"),
        ("P6.7", "Accounting of disclosures"),
        ("P7.1", "Quality of personal information"),
        ("P8.1", "Inquiries, complaints and disputes"),
    ]
    reqs = []
    for code, title, items in groups:
        reqs.append({"ref": code, "title": title, "is_domain": True})
        reqs += [{"ref": f"{code}.{i}", "title": t, "parent": code} for i, t in enumerate(items, 1)]
    reqs.append({"ref": "P", "title": "Privacy", "is_domain": True})
    reqs += [{"ref": r, "title": t, "parent": "P"} for r, t in privacy]
    assert sum(1 for r in reqs if not r.get("is_domain")) == 61
    write(
        "soc2-tsc-2017.yaml",
        INDICATIVE,
        {
            "code": "SOC2-TSC-2017",
            "name": "SOC 2 Trust Services Criteria",
            "version": "2017 (rev. 2022)",
            "publisher": "AICPA",
            "source_url": "https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022",
            "licence_note": "AICPA copyright: criterion identifiers and paraphrased titles only.",
            "content_level": "reference",
            "description": "Common criteria (security) plus availability, confidentiality, processing "
            "integrity and privacy categories. Mark categories outside your report scope N/A.",
        },
        reqs,
    )


# ----------------------------------------------------------------------------- CIS v8
def cis() -> None:
    controls = [
        (
            "Inventory and control of enterprise assets",
            [
                "Maintain a detailed enterprise asset inventory",
                "Address unauthorised assets",
                "Use an active asset discovery tool",
                "Use DHCP logging to update the asset inventory",
                "Use a passive asset discovery tool",
            ],
        ),
        (
            "Inventory and control of software assets",
            [
                "Maintain a software inventory",
                "Ensure authorised software is supported",
                "Address unauthorised software",
                "Use automated software inventory tools",
                "Allowlist authorised software",
                "Allowlist authorised libraries",
                "Allowlist authorised scripts",
            ],
        ),
        (
            "Data protection",
            [
                "Data management process",
                "Data inventory",
                "Data access control lists",
                "Enforce data retention",
                "Securely dispose of data",
                "Encrypt data on end-user devices",
                "Data classification scheme",
                "Document data flows",
                "Encrypt data on removable media",
                "Encrypt sensitive data in transit",
                "Encrypt sensitive data at rest",
                "Segment data processing and storage by sensitivity",
                "Deploy data loss prevention",
                "Log sensitive data access",
            ],
        ),
        (
            "Secure configuration of enterprise assets and software",
            [
                "Secure configuration process",
                "Secure configuration process for network infrastructure",
                "Automatic session locking",
                "Firewall on servers",
                "Firewall on end-user devices",
                "Securely manage enterprise assets and software",
                "Manage default accounts",
                "Uninstall or disable unnecessary services",
                "Configure trusted DNS servers",
                "Automatic lockout on portable devices",
                "Remote wipe for portable devices",
                "Separate enterprise workspaces on mobile devices",
            ],
        ),
        (
            "Account management",
            [
                "Inventory of accounts",
                "Use unique passwords",
                "Disable dormant accounts",
                "Restrict administrator privileges to dedicated accounts",
                "Inventory of service accounts",
                "Centralise account management",
            ],
        ),
        (
            "Access control management",
            [
                "Access granting process",
                "Access revoking process",
                "MFA for externally-exposed applications",
                "MFA for remote network access",
                "MFA for administrative access",
                "Inventory of authentication and authorisation systems",
                "Centralise access control",
                "Role-based access control",
            ],
        ),
        (
            "Continuous vulnerability management",
            [
                "Vulnerability management process",
                "Remediation process",
                "Automated operating system patch management",
                "Automated application patch management",
                "Automated vulnerability scans of internal assets",
                "Automated vulnerability scans of externally-exposed assets",
                "Remediate detected vulnerabilities",
            ],
        ),
        (
            "Audit log management",
            [
                "Audit log management process",
                "Collect audit logs",
                "Adequate audit log storage",
                "Standardise time synchronisation",
                "Collect detailed audit logs",
                "Collect DNS query audit logs",
                "Collect URL request audit logs",
                "Collect command-line audit logs",
                "Centralise audit logs",
                "Retain audit logs",
                "Conduct audit log reviews",
                "Collect service provider logs",
            ],
        ),
        (
            "Email and web browser protections",
            [
                "Use only supported browsers and email clients",
                "Use DNS filtering services",
                "Network-based URL filters",
                "Restrict unnecessary browser and email extensions",
                "Implement DMARC",
                "Block unnecessary file types",
                "Email server anti-malware",
            ],
        ),
        (
            "Malware defenses",
            [
                "Deploy anti-malware software",
                "Automatic anti-malware signature updates",
                "Disable autorun and autoplay for removable media",
                "Automatic anti-malware scanning of removable media",
                "Enable anti-exploitation features",
                "Centrally manage anti-malware",
                "Behaviour-based anti-malware",
            ],
        ),
        (
            "Data recovery",
            [
                "Data recovery process",
                "Automated backups",
                "Protect recovery data",
                "Isolated instance of recovery data",
                "Test data recovery",
            ],
        ),
        (
            "Network infrastructure management",
            [
                "Keep network infrastructure up to date",
                "Secure network architecture",
                "Securely manage network infrastructure",
                "Network architecture documentation",
                "Centralise network authentication, authorisation and auditing",
                "Secure network management and communication protocols",
                "Remote devices connect via VPN and AAA",
                "Dedicated resources for administrative work",
            ],
        ),
        (
            "Network monitoring and defense",
            [
                "Centralise security event alerting",
                "Host-based intrusion detection",
                "Network intrusion detection",
                "Traffic filtering between network segments",
                "Manage access control for remote assets",
                "Collect network traffic flow logs",
                "Host-based intrusion prevention",
                "Network intrusion prevention",
                "Port-level access control",
                "Application layer filtering",
                "Tune security event alerting thresholds",
            ],
        ),
        (
            "Security awareness and skills training",
            [
                "Security awareness programme",
                "Recognise social engineering attacks",
                "Authentication best practices",
                "Data handling best practices",
                "Causes of unintentional data exposure",
                "Recognise and report security incidents",
                "Recognise missing security updates",
                "Dangers of insecure networks",
                "Role-specific security training",
            ],
        ),
        (
            "Service provider management",
            [
                "Inventory of service providers",
                "Service provider management policy",
                "Classify service providers",
                "Security requirements in service provider contracts",
                "Assess service providers",
                "Monitor service providers",
                "Securely decommission service providers",
            ],
        ),
        (
            "Application software security",
            [
                "Secure application development process",
                "Process to accept and address vulnerabilities",
                "Root cause analysis of security vulnerabilities",
                "Inventory of third-party software components",
                "Up-to-date and trusted third-party components",
                "Severity rating for application vulnerabilities",
                "Standard hardening templates for application infrastructure",
                "Separate production and non-production systems",
                "Train developers in secure coding",
                "Secure design principles",
                "Vetted modules for application security components",
                "Code-level security checks",
                "Application penetration testing",
                "Threat modelling",
            ],
        ),
        (
            "Incident response management",
            [
                "Designate incident handling personnel",
                "Contact information for incident reporting",
                "Process for reporting incidents",
                "Incident response process",
                "Assign key roles and responsibilities",
                "Communication during incident response",
                "Routine incident response exercises",
                "Post-incident reviews",
                "Security incident thresholds",
            ],
        ),
        (
            "Penetration testing",
            [
                "Penetration testing programme",
                "Periodic external penetration tests",
                "Remediate penetration test findings",
                "Validate security measures",
                "Periodic internal penetration tests",
            ],
        ),
    ]
    reqs = []
    for n, (title, safeguards) in enumerate(controls, 1):
        reqs.append({"ref": str(n), "title": title, "is_domain": True})
        reqs += [
            {"ref": f"{n}.{i}", "title": t, "parent": str(n)} for i, t in enumerate(safeguards, 1)
        ]
    assert sum(1 for r in reqs if not r.get("is_domain")) == 153
    write(
        "cis-controls-v8.yaml",
        INDICATIVE,
        {
            "code": "CIS-V8",
            "name": "CIS Critical Security Controls v8",
            "version": "8",
            "publisher": "Center for Internet Security",
            "source_url": "https://www.cisecurity.org/controls/v8",
            "licence_note": "CIS Controls are CC BY-NC-SA 4.0: safeguard numbers and paraphrased titles only. "
            "Implementation Groups are not included.",
            "content_level": "reference",
            "description": "18 controls and 153 safeguards. Use N/A to scope to your Implementation Group.",
        },
        reqs,
    )


# ----------------------------------------------------------------------------- HIPAA
def hipaa() -> None:
    R, A = "Required", "Addressable"
    sections = [
        (
            "164.308",
            "Administrative safeguards",
            [
                (
                    "164.308(a)(1)",
                    "Security management process",
                    [
                        (
                            "(ii)(A)",
                            "Risk analysis",
                            R,
                            "Conduct an accurate and thorough assessment of risks and vulnerabilities to ePHI.",
                        ),
                        (
                            "(ii)(B)",
                            "Risk management",
                            R,
                            "Implement measures that reduce risks and vulnerabilities to a reasonable and appropriate level.",
                        ),
                        (
                            "(ii)(C)",
                            "Sanction policy",
                            R,
                            "Apply sanctions to workforce members who fail to comply with security policies.",
                        ),
                        (
                            "(ii)(D)",
                            "Information system activity review",
                            R,
                            "Regularly review records of system activity such as audit logs, access and incident reports.",
                        ),
                    ],
                ),
                (
                    "164.308(a)(2)",
                    "Assigned security responsibility",
                    R,
                    "Identify the security official responsible for security policies and procedures.",
                ),
                (
                    "164.308(a)(3)",
                    "Workforce security",
                    [
                        (
                            "(ii)(A)",
                            "Authorization and/or supervision",
                            A,
                            "Authorise or supervise workforce members who work with ePHI.",
                        ),
                        (
                            "(ii)(B)",
                            "Workforce clearance procedure",
                            A,
                            "Determine that a workforce member's access to ePHI is appropriate.",
                        ),
                        (
                            "(ii)(C)",
                            "Termination procedures",
                            A,
                            "End access to ePHI when employment or engagement ends.",
                        ),
                    ],
                ),
                (
                    "164.308(a)(4)",
                    "Information access management",
                    [
                        (
                            "(ii)(A)",
                            "Isolating health care clearinghouse functions",
                            R,
                            "Protect ePHI of a clearinghouse from the larger organisation.",
                        ),
                        (
                            "(ii)(B)",
                            "Access authorization",
                            A,
                            "Policies for granting access to ePHI.",
                        ),
                        (
                            "(ii)(C)",
                            "Access establishment and modification",
                            A,
                            "Establish, document, review and modify access rights.",
                        ),
                    ],
                ),
                (
                    "164.308(a)(5)",
                    "Security awareness and training",
                    [
                        (
                            "(ii)(A)",
                            "Security reminders",
                            A,
                            "Periodic security updates to the workforce.",
                        ),
                        (
                            "(ii)(B)",
                            "Protection from malicious software",
                            A,
                            "Procedures to guard against, detect and report malicious software.",
                        ),
                        (
                            "(ii)(C)",
                            "Log-in monitoring",
                            A,
                            "Monitor log-in attempts and report discrepancies.",
                        ),
                        (
                            "(ii)(D)",
                            "Password management",
                            A,
                            "Procedures for creating, changing and safeguarding passwords.",
                        ),
                    ],
                ),
                (
                    "164.308(a)(6)",
                    "Security incident procedures",
                    [
                        (
                            "(ii)",
                            "Response and reporting",
                            R,
                            "Identify, respond to, mitigate and document security incidents.",
                        ),
                    ],
                ),
                (
                    "164.308(a)(7)",
                    "Contingency plan",
                    [
                        (
                            "(ii)(A)",
                            "Data backup plan",
                            R,
                            "Create and maintain retrievable exact copies of ePHI.",
                        ),
                        (
                            "(ii)(B)",
                            "Disaster recovery plan",
                            R,
                            "Procedures to restore any loss of data.",
                        ),
                        (
                            "(ii)(C)",
                            "Emergency mode operation plan",
                            R,
                            "Continue critical processes protecting ePHI during an emergency.",
                        ),
                        (
                            "(ii)(D)",
                            "Testing and revision procedures",
                            A,
                            "Periodically test and revise contingency plans.",
                        ),
                        (
                            "(ii)(E)",
                            "Applications and data criticality analysis",
                            A,
                            "Assess the relative criticality of applications and data.",
                        ),
                    ],
                ),
                (
                    "164.308(a)(8)",
                    "Evaluation",
                    R,
                    "Periodic technical and non-technical evaluation of security against the rule.",
                ),
                (
                    "164.308(b)(1)",
                    "Business associate contracts and other arrangements",
                    [
                        (
                            "(b)(3)",
                            "Written contract or other arrangement",
                            R,
                            "Document business associate assurances in a written contract or arrangement.",
                        ),
                    ],
                ),
            ],
        ),
        (
            "164.310",
            "Physical safeguards",
            [
                (
                    "164.310(a)(1)",
                    "Facility access controls",
                    [
                        (
                            "(a)(2)(i)",
                            "Contingency operations",
                            A,
                            "Allow facility access to restore data during emergencies.",
                        ),
                        (
                            "(a)(2)(ii)",
                            "Facility security plan",
                            A,
                            "Safeguard facilities and equipment from unauthorised access, tampering and theft.",
                        ),
                        (
                            "(a)(2)(iii)",
                            "Access control and validation procedures",
                            A,
                            "Control and validate a person's access to facilities based on role.",
                        ),
                        (
                            "(a)(2)(iv)",
                            "Maintenance records",
                            A,
                            "Document repairs and modifications to physical security components.",
                        ),
                    ],
                ),
                (
                    "164.310(b)",
                    "Workstation use",
                    R,
                    "Specify proper functions and physical surroundings of workstations accessing ePHI.",
                ),
                (
                    "164.310(c)",
                    "Workstation security",
                    R,
                    "Physical safeguards restricting workstation access to authorised users.",
                ),
                (
                    "164.310(d)(1)",
                    "Device and media controls",
                    [
                        (
                            "(d)(2)(i)",
                            "Disposal",
                            R,
                            "Final disposition of ePHI and the hardware or media storing it.",
                        ),
                        ("(d)(2)(ii)", "Media re-use", R, "Remove ePHI from media before re-use."),
                        (
                            "(d)(2)(iii)",
                            "Accountability",
                            A,
                            "Record movements of hardware and media and the person responsible.",
                        ),
                        (
                            "(d)(2)(iv)",
                            "Data backup and storage",
                            A,
                            "Create a retrievable copy of ePHI before moving equipment.",
                        ),
                    ],
                ),
            ],
        ),
        (
            "164.312",
            "Technical safeguards",
            [
                (
                    "164.312(a)(1)",
                    "Access control",
                    [
                        (
                            "(a)(2)(i)",
                            "Unique user identification",
                            R,
                            "Assign a unique name and/or number to identify and track users.",
                        ),
                        (
                            "(a)(2)(ii)",
                            "Emergency access procedure",
                            R,
                            "Obtain necessary ePHI during an emergency.",
                        ),
                        (
                            "(a)(2)(iii)",
                            "Automatic logoff",
                            A,
                            "Terminate electronic sessions after a period of inactivity.",
                        ),
                        (
                            "(a)(2)(iv)",
                            "Encryption and decryption",
                            A,
                            "Encrypt and decrypt ePHI at rest.",
                        ),
                    ],
                ),
                (
                    "164.312(b)",
                    "Audit controls",
                    R,
                    "Record and examine activity in systems containing ePHI.",
                ),
                (
                    "164.312(c)(1)",
                    "Integrity",
                    [
                        (
                            "(c)(2)",
                            "Mechanism to authenticate electronic PHI",
                            A,
                            "Corroborate that ePHI has not been altered or destroyed improperly.",
                        ),
                    ],
                ),
                (
                    "164.312(d)",
                    "Person or entity authentication",
                    R,
                    "Verify that a person or entity seeking access is who they claim to be.",
                ),
                (
                    "164.312(e)(1)",
                    "Transmission security",
                    [
                        (
                            "(e)(2)(i)",
                            "Integrity controls",
                            A,
                            "Ensure transmitted ePHI is not improperly modified without detection.",
                        ),
                        (
                            "(e)(2)(ii)",
                            "Encryption",
                            A,
                            "Encrypt ePHI in transit whenever deemed appropriate.",
                        ),
                    ],
                ),
            ],
        ),
        (
            "164.314",
            "Organizational requirements",
            [
                (
                    "164.314(a)(1)",
                    "Business associate contracts or other arrangements",
                    R,
                    "Contracts must require business associates to safeguard ePHI and report incidents.",
                ),
                (
                    "164.314(b)(1)",
                    "Requirements for group health plans",
                    R,
                    "Plan documents must require the sponsor to safeguard ePHI.",
                ),
            ],
        ),
        (
            "164.316",
            "Policies, procedures and documentation",
            [
                (
                    "164.316(a)",
                    "Policies and procedures",
                    R,
                    "Implement reasonable and appropriate policies and procedures to comply with the rule.",
                ),
                (
                    "164.316(b)(1)",
                    "Documentation",
                    [
                        (
                            "(b)(2)(i)",
                            "Time limit",
                            R,
                            "Retain documentation for 6 years from creation or last effective date.",
                        ),
                        (
                            "(b)(2)(ii)",
                            "Availability",
                            R,
                            "Make documentation available to those responsible for implementing procedures.",
                        ),
                        (
                            "(b)(2)(iii)",
                            "Updates",
                            R,
                            "Review documentation periodically and update in response to changes.",
                        ),
                    ],
                ),
            ],
        ),
    ]
    reqs = []
    for sec, title, items in sections:
        reqs.append({"ref": sec, "title": f"§{sec} {title}", "is_domain": True})
        for item in items:
            ref, std_title, *rest = item
            if isinstance(rest[0], list):  # standard with implementation specifications
                reqs.append({"ref": ref, "title": std_title, "parent": sec, "is_domain": True})
                for suffix, spec, kind, summary in rest[0]:
                    reqs.append(
                        {
                            "ref": _hipaa_ref(ref, suffix),
                            "title": f"{spec} ({kind})",
                            "text": summary,
                            "parent": ref,
                        }
                    )
            else:
                kind, summary = rest
                reqs.append(
                    {"ref": ref, "title": f"{std_title} ({kind})", "text": summary, "parent": sec}
                )
    write(
        "hipaa-security-rule.yaml",
        INDICATIVE
        + "# Plain-language summaries, not the regulatory text: see 45 CFR Part 164 Subpart C.\n",
        {
            "code": "HIPAA-SR",
            "name": "HIPAA Security Rule",
            "version": "45 CFR 164 Subpart C",
            "publisher": "US Department of Health and Human Services",
            "source_url": "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C",
            "licence_note": "US federal regulation (public domain). Section headings are official; "
            "descriptions are plain-language summaries. Check eCFR for the current text and amendments.",
            "content_level": "summary",
            "description": "Administrative, physical and technical safeguards for electronic protected "
            "health information (ePHI). (R) = required, (A) = addressable implementation specification.",
        },
        reqs,
    )


def _hipaa_ref(standard: str, suffix: str) -> str:
    """Specs written "(ii)..." extend the standard; others extend the section.

    164.308(a)(1) + (ii)(A) -> 164.308(a)(1)(ii)(A)
    164.310(a)(1) + (a)(2)(i) -> 164.310(a)(2)(i);  164.308(b)(1) + (b)(3) -> 164.308(b)(3)
    """
    if suffix.startswith("(ii)"):
        return standard + suffix
    return standard.split("(")[0] + suffix


# ----------------------------------------------------------------------------- DPDP Act 2023
def dpdp() -> None:
    chapters = [
        (
            "CH-II",
            "Obligations of Data Fiduciary",
            [
                (
                    "S.4",
                    "Grounds for processing personal data",
                    "Process personal data only for a lawful purpose, with the Data Principal's consent or for a legitimate use under section 7.",
                ),
                (
                    "S.5",
                    "Notice",
                    "Give an itemised notice of the personal data and purpose, how to exercise rights and how to complain to the Board, with or before the consent request (and for consents given before the Act).",
                ),
                (
                    "S.6",
                    "Consent",
                    "Consent must be free, specific, informed, unconditional and unambiguous by clear affirmative action, limited to necessary data, and as easy to withdraw as to give; consent managers may be used.",
                ),
                (
                    "S.7",
                    "Certain legitimate uses",
                    "Identify processing relying on legitimate uses (e.g. data voluntarily provided for a specified purpose, legal obligations, employment, medical emergencies) instead of consent.",
                ),
                (
                    "S.8(1)",
                    "Responsibility for compliance",
                    "The Data Fiduciary is responsible for compliance, including for processing done on its behalf by a Data Processor.",
                ),
                (
                    "S.8(2)",
                    "Data Processors under valid contract",
                    "Engage or involve Data Processors only under a valid contract.",
                ),
                (
                    "S.8(3)",
                    "Completeness, accuracy and consistency",
                    "Ensure personal data is complete, accurate and consistent where used for decisions about the Data Principal or disclosed to another Data Fiduciary.",
                ),
                (
                    "S.8(4)",
                    "Technical and organisational measures",
                    "Implement appropriate technical and organisational measures to ensure effective observance of the Act.",
                ),
                (
                    "S.8(5)",
                    "Reasonable security safeguards",
                    "Protect personal data in your possession or control, including processing by Data Processors, with reasonable security safeguards to prevent a personal data breach.",
                ),
                (
                    "S.8(6)",
                    "Personal data breach intimation",
                    "Inform the Data Protection Board and each affected Data Principal of a personal data breach, in the form and manner prescribed.",
                ),
                (
                    "S.8(7)",
                    "Erasure and retention limits",
                    "Erase personal data (and have processors erase it) once consent is withdrawn or the purpose is no longer served, unless retention is required by law.",
                ),
                (
                    "S.8(9)",
                    "Published contact for data protection queries",
                    "Publish the business contact information of the Data Protection Officer or a person able to answer questions about processing.",
                ),
                (
                    "S.8(10)",
                    "Grievance redressal mechanism",
                    "Establish an effective mechanism to redress grievances of Data Principals.",
                ),
                (
                    "S.9",
                    "Processing personal data of children",
                    "Obtain verifiable parental consent; do not process in ways likely to harm a child's well-being, and no tracking, behavioural monitoring or targeted advertising directed at children.",
                ),
                (
                    "S.10",
                    "Additional obligations of Significant Data Fiduciaries",
                    "If notified as significant: appoint a Data Protection Officer based in India, an independent data auditor, and carry out periodic DPIAs and audits.",
                ),
            ],
        ),
        (
            "CH-III",
            "Rights of Data Principal (fiduciary duties to support them)",
            [
                (
                    "S.11",
                    "Right to access information about personal data",
                    "Provide a summary of personal data processed, processing activities and the identities of others it was shared with, on request.",
                ),
                (
                    "S.12",
                    "Right to correction and erasure",
                    "Correct, complete, update or erase personal data on request, subject to legal retention requirements.",
                ),
                (
                    "S.13",
                    "Right of grievance redressal",
                    "Respond to grievances within the prescribed period before the Data Principal approaches the Board.",
                ),
                (
                    "S.14",
                    "Right to nominate",
                    "Allow Data Principals to nominate a person to exercise their rights in case of death or incapacity.",
                ),
            ],
        ),
        (
            "CH-IV",
            "Special provisions",
            [
                (
                    "S.16",
                    "Processing outside India",
                    "Do not transfer personal data to countries or territories restricted by Central Government notification.",
                ),
            ],
        ),
    ]
    reqs = []
    for ch, title, items in chapters:
        reqs.append({"ref": ch, "title": title, "is_domain": True})
        reqs += [{"ref": r, "title": t, "text": s, "parent": ch} for r, t, s in items]
    write(
        "india-dpdp-2023.yaml",
        INDICATIVE
        + "# Plain-language summaries of the Act's obligations, not the statutory text.\n",
        {
            "code": "DPDP-2023",
            "name": "India Digital Personal Data Protection Act, 2023",
            "version": "2023 (No. 22 of 2023)",
            "publisher": "Government of India (MeitY)",
            "source_url": "https://www.meity.gov.in/data-protection-framework",
            "licence_note": "Indian statute. Section headings follow the Act; descriptions are plain-language "
            "summaries. Read with the DPDP Rules for prescribed forms and timelines.",
            "content_level": "summary",
            "description": "Obligations of Data Fiduciaries processing digital personal data in India.",
        },
        reqs,
    )


if __name__ == "__main__":
    iso()
    soc2()
    cis()
    hipaa()
    dpdp()
