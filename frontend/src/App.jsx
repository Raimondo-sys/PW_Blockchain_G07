import { useState } from "react";

const BLU = {
  900:"#042C53",800:"#0C447C",600:"#185FA5",400:"#378ADD",
  200:"#85B7EB",100:"#B5D4F4",50:"#E6F1FB"
};
const GRY = {800:"#444441",600:"#5F5E5A",400:"#888780",200:"#B4B2A9",100:"#D3D1C7",50:"#F5F4F0"};
const RED = {bg:"#FCEBEB",border:"#F09595",text:"#A32D2D"};
const GRN = {bg:"#EAF3DE",border:"#97C459",text:"#3B6D11"};
const AMB = {bg:"#FAEEDA",border:"#FAC775",text:"#854F0B"};

const DATA = {
  system:{paCount:4,auditorCount:2,auditWindowOpen:true,auditWindowEnd:"2026-05-31T14:30:00Z"},
  domains:[
    {name:"NETWORK",     idx:0, active:true,  version:2, safeDefault:true,  safeDefaultCid:"QmSafe1_NETWORK"},
    {name:"SYSTEM",      idx:1, active:false, version:0, safeDefault:false, safeDefaultCid:null},
    {name:"APPLICATION", idx:2, active:false, version:0, safeDefault:false, safeDefaultCid:null},
  ],
  policies:[
    {
      // NETWORK v2 — Active — corresponds to the second certifyPolicy in full_flow.ts
      proposalId:"0xa3f8d1c2b5e7f901a2b3c4d5e6f70819",
      domain:"NETWORK", version:2, status:"Active",
      cid:"QmPayload2_NETWORK_v2_cifrato",
      cidKeyDistrib:"QmKDD2_post_cert_Auditor_AA",   // updated post-certification (step 5 of the flow)
      safeDefaultCid:"QmSafe1_NETWORK",
      replacesId:"0xb7c2e4f5a1d3e6f802b4c5d6e7f80920",
      certifiedAt:"2026-05-28T14:30:00Z",
      updatedAt:"2026-05-28T15:00:00Z",
      // Content of the policy document read from disk in the scripts (network_policy_v2.json)
      rules:[
        {eventType:"authentication_failure", retention:"P180D", severity:"HIGH",     threshold:3},
        {eventType:"privileged_access",      retention:"P365D", severity:"CRITICAL", threshold:1},
        {eventType:"network_anomaly",        retention:"P60D",  severity:"MEDIUM",   threshold:5},
        {eventType:"dns_anomaly",            retention:"P90D",  severity:"HIGH",     threshold:1},
        {eventType:"zero_day_indicator",     retention:"P365D", severity:"CRITICAL", threshold:1},
      ],
      enforcement:{mandatory:true, gracePeriod:"P3D", auditFrequency:"weekly"},
      // EnforcementRecord[] array from the PolicyRegistry — confirmEnforcement()
      enforcements:[
        {aaDID:"did:ethr:aa1", appliedCid:"QmPayload2_NETWORK_v2_cifrato", confirmedAt:"2026-05-28T15:00:00Z"},
      ],
    },
    {
      // NETWORK v1 — Archived — replaced by v2 in the atomic transition
      proposalId:"0xb7c2e4f5a1d3e6f802b4c5d6e7f80920",
      domain:"NETWORK", version:1, status:"Archived",
      cid:"QmPayload1_NETWORK_v1_cifrato",
      cidKeyDistrib:"QmKDD1_post_cert_Auditor_AA",
      safeDefaultCid:"QmSafe1_NETWORK",              // declared at the first certifyPolicy
      replacesId:"0x0000000000000000000000000000000000000000000000000000000000000000",
      certifiedAt:"2026-05-20T09:15:00Z",
      updatedAt:"2026-05-28T14:30:00Z",
      rules:[
        {eventType:"authentication_failure", retention:"P90D",  severity:"HIGH",     threshold:5},
        {eventType:"privileged_access",      retention:"P365D", severity:"CRITICAL", threshold:1},
        {eventType:"network_anomaly",        retention:"P30D",  severity:"MEDIUM",   threshold:10},
      ],
      enforcement:{mandatory:true, gracePeriod:"P7D", auditFrequency:"monthly"},
      enforcements:[
        {aaDID:"did:ethr:aa1", appliedCid:"QmPayload1_NETWORK_v1_cifrato", confirmedAt:"2026-05-20T16:30:00Z"},
      ],
    },
  ],
  proposals:[
    {
      // SYSTEM proposal in Endorsed state — in voting
      proposalId:"0xc9d3f6a7b2e4f508c1d2e3f4a5b60718",
      domain:"SYSTEM", status:"Endorsed",
      submitterDID:"did:ethr:deg2",
      ppDID:"did:ethr:pp2",
      endorserDID:"did:ethr:pa2",
      quorumSnapshot:4, quorumRequired:3, votesFor:1,
      cid:"QmPayload_SYSTEM_v1_cifrato",
      cidKeyDistrib:"QmKDD_SYSTEM_deliberativa",   // only PA and PP in the deliberative phase
      safeDefaultCid:"QmSafe1_SYSTEM",             // first policy on SYSTEM → declares safe default
      replacesId:"0x0000000000000000000000000000000000000000000000000000000000000000",
      submittedAt:"2026-05-30T08:00:00Z",
      forwardedAt:"2026-05-30T09:00:00Z",
      endorsedAt:"2026-05-30T10:00:00Z",
      rejectedAt:null,
      rejectReason:null,
      voters:[
        {did:"did:ethr:pa1", voted:true,  support:true},
        {did:"did:ethr:pa2", voted:false, support:null},
        {did:"did:ethr:pa3", voted:false, support:null},
        {did:"did:ethr:pa4", voted:false, support:null},
      ],
    },
    {
      // NETWORK proposal rejected by the PP (ProposalRejected on-chain with reason)
      proposalId:"0xd4e5g8b9c3f5a701d2e3f4a5b6c70819",
      domain:"NETWORK", status:"Rejected",
      submitterDID:"did:ethr:deg1",
      ppDID:"did:ethr:pp1",
      endorserDID:null,
      quorumSnapshot:4, quorumRequired:3, votesFor:0,
      cid:"QmPayload_NETWORK_rejected_cifrato",
      cidKeyDistrib:"QmKDD_NETWORK_rejected",
      safeDefaultCid:null,
      replacesId:"0xb7c2e4f5a1d3e6f802b4c5d6e7f80920",
      submittedAt:"2026-05-25T11:00:00Z",
      forwardedAt:null,
      endorsedAt:null,
      rejectedAt:"2026-05-25T12:00:00Z",
      // Reason tracked on-chain in rejectProposal() — WP2 §2.2 phase 2
      rejectReason:"Insufficient DNS domain coverage compared to NIS2 standards.",
      voters:[],
    },
  ],
  entities:[
    // PA — anywise DID, empty scope, authenticates directly via msg.sender
    {did:"did:ethr:pa1", role:"PA", status:"Active", address:"0xAbC1...2345", registeredBy:"genesis", scope:[], pairwise:false, expiresAt:null},
    {did:"did:ethr:pa2", role:"PA", status:"Active", address:"0xDeF3...6789", registeredBy:"genesis", scope:[], pairwise:false, expiresAt:null},
    {did:"did:ethr:pa3", role:"PA", status:"Active", address:"0xGhI5...0ABC", registeredBy:"genesis", scope:[], pairwise:false, expiresAt:null},
    {did:"did:ethr:pa4", role:"PA", status:"Active", address:"0xJkL7...CDEF", registeredBy:"genesis", scope:[], pairwise:false, expiresAt:null},
    // AUDITOR — anywise DID, global scope [N,S,A], appointed by quorum
    {did:"did:ethr:aud1", role:"AUDITOR", status:"Active", address:"0xMnO9...EF01", registeredBy:"genesis", scope:["NETWORK","SYSTEM","APPLICATION"], pairwise:false, expiresAt:null},
    {did:"did:ethr:aud2", role:"AUDITOR", status:"Active", address:"0xPqR2...2345", registeredBy:"genesis", scope:["NETWORK","SYSTEM","APPLICATION"], pairwise:false, expiresAt:null},
    // PP — anywise DID, full scope [N,S,A], delegated by PA
    {did:"did:ethr:pp1", role:"PP", status:"Active", address:"0xStU4...6789", registeredBy:"did:ethr:pa1", scope:["NETWORK","SYSTEM","APPLICATION"], pairwise:false, expiresAt:null},
    {did:"did:ethr:pp2", role:"PP", status:"Active", address:"0xVwX6...ABCD", registeredBy:"did:ethr:pa2", scope:["NETWORK","SYSTEM","APPLICATION"], pairwise:false, expiresAt:null},
    // DEG — anywise DID, single scope, delegated by PP
    {did:"did:ethr:deg1", role:"DEG", status:"Active", address:"0xYzA8...EF01", registeredBy:"did:ethr:pp1", scope:["NETWORK"],  pairwise:false, expiresAt:null},
    {did:"did:ethr:deg2", role:"DEG", status:"Active", address:"0xBcD0...2345", registeredBy:"did:ethr:pp2", scope:["SYSTEM"],   pairwise:false, expiresAt:null},
    // AA — pairwise DID, future expiration, registered by PA with TemporaryVC
    {did:"did:ethr:aa1",  role:"AA",  status:"Active",  address:"0xEfG2...6789", registeredBy:"did:ethr:pa1", scope:["NETWORK"], pairwise:true,  expiresAt:"2286-11-20"},
    // EV — pairwise DID, expired — automatically revoked at TemporaryVC expiration
    {did:"did:ethr:ev1",  role:"EV",  status:"Revoked", address:"0xHiJ4...ABCD", registeredBy:"did:ethr:pa1", scope:["NETWORK"], pairwise:true,  expiresAt:"2026-05-10"},
  ],
  // On-chain events — reflect the emits of the final contracts
  // ProposalSubmitted, ProposalForwarded, ProposalEndorsed, VoteCast, PolicyCertified,
  // AuditWindowOpened, KeyDistribUpdated, EnforcementConfirmed, BootstrapFinalized
  events:[
    {block:1052, ts:"2026-05-28T15:00:00Z", type:"EnforcementConfirmed",  actor:"did:ethr:aa1",       detail:"NETWORK v2 — appliedCid verified and confirmed on-chain"},
    {block:1051, ts:"2026-05-28T14:35:00Z", type:"AuditWindowOpened",     actor:"GovernanceContract", detail:"Audit window opened — expires 2026-05-31T14:35:00Z"},
    {block:1051, ts:"2026-05-28T14:30:00Z", type:"PolicyCertified",       actor:"GovernanceContract", detail:"NETWORK v2 certified — 3/3 votes, quorum reached, v1 → Archived"},
    {block:1050, ts:"2026-05-28T14:25:00Z", type:"VoteCast",              actor:"did:ethr:pa3",       detail:"NETWORK v2 — in favor (3/3 → quorum reached)"},
    {block:1049, ts:"2026-05-28T14:20:00Z", type:"VoteCast",              actor:"did:ethr:pa2",       detail:"NETWORK v2 — in favor (2/3)"},
    {block:1048, ts:"2026-05-28T14:15:00Z", type:"VoteCast",              actor:"did:ethr:pa1",       detail:"NETWORK v2 — in favor (1/3)"},
    {block:1047, ts:"2026-05-28T14:10:00Z", type:"ProposalEndorsed",      actor:"did:ethr:pa1",       detail:"Snapshot: 4 active PAs, quorum threshold: 3"},
    {block:1046, ts:"2026-05-28T14:05:00Z", type:"ProposalForwarded",     actor:"did:ethr:pp1",       detail:"NETWORK v2 — forwarded to the PA after off-chain VP verification"},
    {block:1045, ts:"2026-05-28T14:00:00Z", type:"ProposalSubmitted",     actor:"did:ethr:deg1",      detail:"NETWORK v2 — CID: QmPayload2_NETWORK_v2_cifrato"},
    {block:1040, ts:"2026-05-28T13:30:00Z", type:"KeyDistribUpdated",     actor:"did:ethr:pa1",       detail:"NETWORK v1 — KDD updated: Auditor and AA added post-certification"},
    {block:1035, ts:"2026-05-25T12:00:00Z", type:"ProposalRejected",      actor:"did:ethr:pp1",       detail:"NETWORK — rejected: insufficient DNS coverage (tracked on-chain)"},
    {block:1030, ts:"2026-05-20T16:30:00Z", type:"EnforcementConfirmed",  actor:"did:ethr:aa1",       detail:"NETWORK v1 — appliedCid verified and confirmed on-chain"},
    {block:1025, ts:"2026-05-20T13:00:00Z", type:"KeyDistribUpdated",     actor:"did:ethr:pa1",       detail:"NETWORK v1 — KDD updated: Auditor and AA added post-certification"},
    {block:1020, ts:"2026-05-20T09:15:00Z", type:"PolicyCertified",       actor:"GovernanceContract", detail:"NETWORK v1 — first certification, safe default declared on-chain"},
    {block:1001, ts:"2026-05-01T08:00:00Z", type:"BootstrapFinalized",    actor:"deployer",           detail:"4 PAs and 2 Auditors registered — bootstrap completed, system active"},
  ],
};

const ROLE_META = {
  PA:      {label:"Policy Authority",    color:BLU[600],  bg:BLU[50]},
  PP:      {label:"Policy Proposer",     color:BLU[400],  bg:"#EEF6FE"},
  DEG:     {label:"Domain Expert Group", color:"#185FA5", bg:"#E6F1FB"},
  AUDITOR: {label:"Auditor",             color:AMB.text,  bg:AMB.bg},
  AA:      {label:"Application Agent",   color:GRN.text,  bg:GRN.bg},
  EV:      {label:"External Verifier",   color:GRY[600],  bg:GRY[100]},
};

const STATUS_META = {
  Active:   {bg:GRN.bg,   text:GRN.text,   border:GRN.border,   label:"Active"},
  Archived: {bg:GRY[100], text:GRY[600],   border:GRY[200],     label:"Archived"},
  Retired:  {bg:GRY[100], text:GRY[800],   border:GRY[400],     label:"Retired"},
  Proposed: {bg:BLU[50],  text:BLU[800],   border:BLU[200],     label:"Proposed"},
  Forwarded:{bg:"#EEF6FE",text:BLU[600],   border:BLU[200],     label:"Forwarded"},
  Endorsed: {bg:AMB.bg,   text:AMB.text,   border:AMB.border,   label:"Endorsed"},
  Certified:{bg:GRN.bg,   text:GRN.text,   border:GRN.border,   label:"Certified"},
  Rejected: {bg:RED.bg,   text:RED.text,   border:RED.border,   label:"Rejected"},
  Revoked:  {bg:RED.bg,   text:RED.text,   border:RED.border,   label:"Revoked"},
};

const EVENT_META = {
  ProposalSubmitted:   {color:BLU[400],  icon:"ti-file-plus",          label:"Proposal submitted"},
  ProposalForwarded:   {color:BLU[600],  icon:"ti-arrow-right",        label:"Proposal forwarded"},
  ProposalEndorsed:    {color:AMB.text,  icon:"ti-circle-check",       label:"Endorsement"},
  VoteCast:            {color:"#185FA5", icon:"ti-thumb-up",           label:"Vote"},
  PolicyCertified:     {color:GRN.text,  icon:"ti-shield-check",       label:"Policy certified"},
  AuditWindowOpened:   {color:BLU[600],  icon:"ti-eye",                label:"Audit window opened"},
  EnforcementConfirmed:{color:GRN.text,  icon:"ti-device-desktop-check", label:"Enforcement confirmed"},
  KeyDistribUpdated:   {color:"#534AB7", icon:"ti-key",                label:"KD doc updated"},
  ProposalRejected:    {color:RED.text,  icon:"ti-x",                  label:"Proposal rejected"},
  BootstrapFinalized:  {color:BLU[800],  icon:"ti-rocket",             label:"Bootstrap completed"},
};

const SEV_COLOR = {
  CRITICAL:{bg:"#FCEBEB",text:"#A32D2D"},
  HIGH:    {bg:AMB.bg,   text:AMB.text},
  MEDIUM:  {bg:BLU[50],  text:BLU[800]},
  LOW:     {bg:GRY[50],  text:GRY[600]},
};

function fmt(iso){
  if(!iso) return "—";
  const d=new Date(iso);
  return d.toLocaleDateString("en-US",{day:"2-digit",month:"short",year:"numeric"})+" "+
         d.toLocaleTimeString("en-US",{hour:"2-digit",minute:"2-digit"});
}
function fmtShort(iso){
  if(!iso) return "—";
  const d=new Date(iso);
  return d.toLocaleDateString("en-US",{day:"2-digit",month:"short"});
}
function shortDID(did){ if(!did) return "—"; return did.split(":").pop(); }
function shortHash(h,n=8){ if(!h) return "—"; return h.length>n*2+2?`${h.slice(0,n+2)}…${h.slice(-n)}`:h; }

/* ── ATOMIC COMPONENTS ───────────────────────────────────────────────────── */
function Badge({status}){
  const m=STATUS_META[status]||{bg:GRY[100],text:GRY[600],border:GRY[200],label:status};
  return(
    <span style={{
      display:"inline-flex",alignItems:"center",gap:4,
      background:m.bg,color:m.text,
      border:`1px solid ${m.border||m.bg}`,
      borderRadius:20,padding:"2px 10px",fontSize:11,fontWeight:500,
    }}>{m.label}</span>
  );
}

function RoleBadge({role}){
  const m=ROLE_META[role]||{label:role,color:GRY[600],bg:GRY[100]};
  return(
    <span style={{background:m.bg,color:m.color,borderRadius:4,padding:"2px 7px",fontSize:11,fontWeight:500}}>
      {m.label}
    </span>
  );
}

function SeverityBadge({severity}){
  const m=SEV_COLOR[severity]||SEV_COLOR.LOW;
  return(
    <span style={{background:m.bg,color:m.text,borderRadius:4,padding:"1px 6px",fontSize:11,fontWeight:500}}>
      {severity}
    </span>
  );
}

function Card({children,style={}}){
  return(
    <div style={{
      background:"var(--color-background-primary)",
      border:"0.5px solid var(--color-border-tertiary)",
      borderRadius:12,padding:"1rem 1.25rem",
      ...style
    }}>{children}</div>
  );
}

function StatCard({label,value,sub,accent=false}){
  return(
    <div style={{
      background:accent?BLU[600]:"var(--color-background-secondary)",
      borderRadius:8,padding:"1rem",
      color:accent?BLU[50]:"var(--color-text-primary)",
    }}>
      <div style={{fontSize:12,color:accent?BLU[200]:"var(--color-text-secondary)",marginBottom:4}}>{label}</div>
      <div style={{fontSize:26,fontWeight:500}}>{value}</div>
      {sub&&<div style={{fontSize:12,color:accent?BLU[200]:"var(--color-text-secondary)",marginTop:2}}>{sub}</div>}
    </div>
  );
}

function SectionTitle({children}){
  return(
    <h2 style={{fontSize:13,fontWeight:500,color:"var(--color-text-secondary)",
      textTransform:"uppercase",letterSpacing:"0.08em",margin:"0 0 12px"}}>
      {children}
    </h2>
  );
}

function Divider(){
  return <div style={{height:"0.5px",background:"var(--color-border-tertiary)",margin:"12px 0"}}/>;
}

/* ── SIDEBAR ─────────────────────────────────────────────────────────────── */
const NAV=[
  {id:"dashboard", icon:"ti-layout-dashboard", label:"Dashboard"},
  {id:"policies",  icon:"ti-file-text",         label:"Policy Registry"},
  {id:"proposals", icon:"ti-clipboard-list",    label:"Proposals"},
  {id:"identities",icon:"ti-users",             label:"Identities"},
  {id:"audit",     icon:"ti-activity",          label:"Audit Trail"},
];

function Sidebar({view,setView}){
  return(
    <nav style={{
      width:200,background:BLU[900],flexShrink:0,
      display:"flex",flexDirection:"column",
      borderRight:`1px solid ${BLU[800]}`,
    }}>
      <div style={{padding:"20px 16px 16px",borderBottom:`1px solid ${BLU[800]}`}}>
        <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:2}}>
          <i className="ti ti-shield-lock" style={{color:BLU[400],fontSize:18}} aria-hidden/>
          <span style={{color:BLU[50],fontWeight:500,fontSize:14,letterSpacing:"0.01em"}}>PolicyChain</span>
        </div>
        <div style={{color:BLU[400],fontSize:11}}>Governance Dashboard</div>
      </div>
      <div style={{flex:1,padding:"12px 8px"}}>
        {NAV.map(n=>{
          const active=view===n.id;
          return(
            <button key={n.id} onClick={()=>setView(n.id)} style={{
              width:"100%",display:"flex",alignItems:"center",gap:10,
              padding:"8px 10px",borderRadius:8,border:"none",cursor:"pointer",
              background:active?BLU[800]:"transparent",
              color:active?BLU[50]:BLU[300]||"#7EB3E8",
              fontSize:13,fontWeight:active?500:400,
              marginBottom:2,transition:"background 0.15s",
            }}>
              <i className={`ti ${n.icon}`} style={{fontSize:16,flexShrink:0}} aria-hidden/>
              {n.label}
            </button>
          );
        })}
      </div>
      <div style={{padding:"12px 16px",borderTop:`1px solid ${BLU[800]}`}}>
        <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:6}}>
          <span style={{width:7,height:7,borderRadius:"50%",background:GRN.border,display:"inline-block"}}/>
          <span style={{color:BLU[200],fontSize:11}}>System active</span>
        </div>
        <div style={{color:BLU[400],fontSize:10}}>Network: Hardhat PoA</div>
        <div style={{color:BLU[400],fontSize:10}}>4 validator · bootstrap ✓</div>
      </div>
    </nav>
  );
}

/* ── DASHBOARD ────────────────────────────────────────────────────────────── */
function Dashboard(){
  const {system,domains,events}=DATA;
  const activePolicies=DATA.policies.filter(p=>p.status==="Active").length;
  const pendingProposals=DATA.proposals.filter(p=>["Endorsed","Proposed","Forwarded"].includes(p.status)).length;

  return(
    <div>
      <h1 style={{fontSize:20,fontWeight:500,margin:"0 0 20px",color:"var(--color-text-primary)"}}>
        System Overview
      </h1>

      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:24}}>
        <StatCard label="Policy Authority" value={system.paCount} sub="quorum 3/4" accent/>
        <StatCard label="Active auditors" value={system.auditorCount} sub="minimum guaranteed: 2"/>
        <StatCard label="Active policies" value={activePolicies} sub="across 3 domains"/>
        <StatCard label="Pending proposals" value={pendingProposals} sub="in voting"/>
      </div>

      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginBottom:16}}>
        <Card>
          <SectionTitle>Domain Status</SectionTitle>
          {domains.map(d=>(
            <div key={d.name} style={{
              display:"flex",alignItems:"center",justifyContent:"space-between",
              padding:"10px 0",borderBottom:"0.5px solid var(--color-border-tertiary)",
            }}>
              <div style={{display:"flex",alignItems:"center",gap:10}}>
                <i className="ti ti-topology-ring-3" style={{color:BLU[400],fontSize:16}} aria-hidden/>
                <div>
                  <div style={{fontSize:13,fontWeight:500,color:"var(--color-text-primary)"}}>{d.name}</div>
                  {d.active
                    ? <div style={{fontSize:11,color:GRN.text}}>Policy v{d.version} active</div>
                    : <div style={{fontSize:11,color:GRY[400]}}>No active policy</div>
                  }
                </div>
              </div>
              <div style={{display:"flex",flexDirection:"column",alignItems:"flex-end",gap:4}}>
                {d.active ? <Badge status="Active"/> : <Badge status="Archived"/>}
                {d.safeDefault
                  ? <span style={{fontSize:10,color:GRY[400]}}>safe default ✓</span>
                  : <span style={{fontSize:10,color:RED.text}}>no safe default</span>
                }
              </div>
            </div>
          ))}
          <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",paddingTop:10}}>
            <span style={{fontSize:12,color:"var(--color-text-secondary)"}}>Audit window</span>
            <span style={{fontSize:12,fontWeight:500,color:system.auditWindowOpen?GRN.text:RED.text}}>
              {system.auditWindowOpen?"Open":"Closed"} · expires {fmtShort(system.auditWindowEnd)}
            </span>
          </div>
        </Card>

        <Card>
          <SectionTitle>Latest on-chain events</SectionTitle>
          {events.slice(0,6).map((e,i)=>{
            const m=EVENT_META[e.type]||{color:GRY[400],icon:"ti-point",label:e.type};
            return(
              <div key={i} style={{
                display:"flex",alignItems:"flex-start",gap:10,
                padding:"8px 0",
                borderBottom:i<5?"0.5px solid var(--color-border-tertiary)":"none",
              }}>
                <i className={`ti ${m.icon}`} style={{color:m.color,fontSize:15,marginTop:2,flexShrink:0}} aria-hidden/>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{fontSize:12,fontWeight:500,color:"var(--color-text-primary)",
                    whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>
                    {m.label}
                  </div>
                  <div style={{fontSize:11,color:"var(--color-text-secondary)",
                    whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis"}}>
                    {e.detail}
                  </div>
                </div>
                <span style={{fontSize:10,color:GRY[400],flexShrink:0,marginTop:2}}>#{e.block}</span>
              </div>
            );
          })}
        </Card>
      </div>

      <Card>
        <SectionTitle>Quorum pipeline — SYSTEM proposal in voting</SectionTitle>
        {DATA.proposals.filter(p=>p.status==="Endorsed").map(p=>(
          <div key={p.proposalId}>
            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:12}}>
              <Badge status={p.status}/>
              <span style={{fontSize:13,color:"var(--color-text-secondary)"}}>
                Domain {p.domain} · {shortDID(p.submitterDID)} → {shortDID(p.ppDID)} → {shortDID(p.endorserDID)}
              </span>
            </div>
            <div style={{display:"flex",alignItems:"center",gap:4,marginBottom:8}}>
              {[{l:"Proposed",ok:true},{l:"Forwarded",ok:true},{l:"Endorsed",ok:true},{l:"Certified",ok:false}].map((s,i)=>(
                <div key={s.l} style={{display:"flex",alignItems:"center",gap:4}}>
                  <div style={{
                    padding:"4px 12px",borderRadius:20,fontSize:11,fontWeight:500,
                    background:s.ok?BLU[50]:"var(--color-background-secondary)",
                    color:s.ok?BLU[800]:GRY[400],
                    border:`1px solid ${s.ok?BLU[200]:"var(--color-border-tertiary)"}`,
                  }}>{s.l}</div>
                  {i<3&&<i className="ti ti-chevron-right" style={{color:GRY[400],fontSize:12}} aria-hidden/>}
                </div>
              ))}
            </div>
            <div style={{display:"flex",alignItems:"center",gap:8}}>
              <div style={{flex:1,height:6,background:GRY[100],borderRadius:3,overflow:"hidden"}}>
                <div style={{
                  height:"100%",
                  width:`${(p.votesFor/p.quorumRequired)*100}%`,
                  background:BLU[400],borderRadius:3,transition:"width 0.3s",
                }}/>
              </div>
              <span style={{fontSize:12,fontWeight:500,color:"var(--color-text-primary)",whiteSpace:"nowrap"}}>
                {p.votesFor} / {p.quorumRequired} votes
              </span>
            </div>
            <div style={{display:"flex",gap:6,marginTop:8}}>
              {p.voters.map((v,i)=>(
                <div key={i} style={{
                  padding:"3px 10px",borderRadius:20,fontSize:11,
                  background:v.voted?(v.support?GRN.bg:RED.bg):"var(--color-background-secondary)",
                  color:v.voted?(v.support?GRN.text:RED.text):GRY[400],
                  border:`0.5px solid ${v.voted?(v.support?GRN.border:RED.border):"var(--color-border-tertiary)"}`,
                }}>
                  {shortDID(v.did)} {v.voted?(v.support?"✓":"✗"):"·"}
                </div>
              ))}
            </div>
          </div>
        ))}
      </Card>
    </div>
  );
}

/* ── POLICIES ─────────────────────────────────────────────────────────────── */
function Policies(){
  const [filter,setFilter]=useState("All");
  const [expanded,setExpanded]=useState(null);

  const domains=["All","NETWORK","SYSTEM","APPLICATION"];
  const filtered=filter==="All"?DATA.policies:DATA.policies.filter(p=>p.domain===filter);

  return(
    <div>
      <h1 style={{fontSize:20,fontWeight:500,margin:"0 0 20px",color:"var(--color-text-primary)"}}>
        Policy Registry
      </h1>

      <div style={{display:"flex",gap:6,marginBottom:16}}>
        {domains.map(d=>(
          <button key={d} onClick={()=>setFilter(d)} style={{
            padding:"5px 14px",borderRadius:20,border:"0.5px solid",cursor:"pointer",fontSize:12,
            background:filter===d?BLU[600]:"var(--color-background-primary)",
            color:filter===d?BLU[50]:"var(--color-text-secondary)",
            borderColor:filter===d?BLU[600]:"var(--color-border-tertiary)",
            fontWeight:filter===d?500:400,
          }}>{d}</button>
        ))}
      </div>

      <div style={{display:"flex",flexDirection:"column",gap:10}}>
        {filtered.length===0&&(
          <Card><div style={{textAlign:"center",color:GRY[400],fontSize:13,padding:"24px 0"}}>
            No policy for the selected domain.
          </div></Card>
        )}
        {filtered.map(p=>{
          const isOpen=expanded===p.proposalId;
          return(
            <Card key={p.proposalId} style={{
              borderLeft:p.status==="Active"?`3px solid ${BLU[400]}`:"3px solid var(--color-border-tertiary)",
              padding:0,overflow:"hidden",
            }}>
              <button onClick={()=>setExpanded(isOpen?null:p.proposalId)} style={{
                width:"100%",textAlign:"left",background:"none",border:"none",cursor:"pointer",
                padding:"14px 16px",
              }}>
                <div style={{display:"flex",alignItems:"center",justifyContent:"space-between"}}>
                  <div style={{display:"flex",alignItems:"center",gap:12}}>
                    <div>
                      <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:3}}>
                        <span style={{fontSize:14,fontWeight:500,color:"var(--color-text-primary)"}}>
                          {p.domain} — version {p.version}
                        </span>
                        <Badge status={p.status}/>
                      </div>
                      <div style={{fontSize:11,color:"var(--color-text-secondary)",fontFamily:"monospace"}}>
                        {shortHash(p.proposalId)} · {p.rules?.length||0} rules · {fmt(p.certifiedAt)}
                      </div>
                    </div>
                  </div>
                  <i className={`ti ${isOpen?"ti-chevron-up":"ti-chevron-down"}`}
                     style={{color:GRY[400],fontSize:16}} aria-hidden/>
                </div>
              </button>

              {isOpen&&(
                <div style={{borderTop:"0.5px solid var(--color-border-tertiary)",padding:"14px 16px"}}>
                  <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:14}}>
                    <div>
                      <div style={{fontSize:11,color:"var(--color-text-secondary)",marginBottom:2}}>CID payload</div>
                      <code style={{fontSize:11,color:"var(--color-text-primary)"}}>{p.cid}</code>
                    </div>
                    <div>
                      {/* cidKeyDistrib — aligned to the final PolicyRegistry field */}
                      <div style={{fontSize:11,color:"var(--color-text-secondary)",marginBottom:2}}>CID key distribution</div>
                      <code style={{fontSize:11,color:"var(--color-text-primary)"}}>{p.cidKeyDistrib}</code>
                    </div>
                    <div>
                      <div style={{fontSize:11,color:"var(--color-text-secondary)",marginBottom:2}}>Safe default CID</div>
                      <code style={{fontSize:11,color:"var(--color-text-primary)"}}>{p.safeDefaultCid||"—"}</code>
                    </div>
                    <div>
                      {/* replacesId — explicit reference to the previous version */}
                      <div style={{fontSize:11,color:"var(--color-text-secondary)",marginBottom:2}}>Replaces</div>
                      <code style={{fontSize:11,color:"var(--color-text-primary)"}}>
                        {p.replacesId && p.replacesId!=="0x"+"00".repeat(32)
                          ? shortHash(p.replacesId)
                          : "—  (first version)"}
                      </code>
                    </div>
                    <div>
                      <div style={{fontSize:11,color:"var(--color-text-secondary)",marginBottom:2}}>Grace period</div>
                      <span style={{fontSize:12}}>{p.enforcement?.gracePeriod||"—"}</span>
                    </div>
                    <div>
                      <div style={{fontSize:11,color:"var(--color-text-secondary)",marginBottom:2}}>Audit frequency</div>
                      <span style={{fontSize:12}}>{p.enforcement?.auditFrequency||"—"}</span>
                    </div>
                  </div>

                  {p.rules&&p.rules.length>0&&(
                    <>
                      <SectionTitle>Logging rules</SectionTitle>
                      <div style={{border:"0.5px solid var(--color-border-tertiary)",borderRadius:8,overflow:"hidden"}}>
                        <div style={{
                          display:"grid",gridTemplateColumns:"2fr 1fr 1fr 80px",
                          padding:"7px 12px",background:"var(--color-background-secondary)",
                          fontSize:11,color:"var(--color-text-secondary)",fontWeight:500,
                        }}>
                          <span>Event</span><span>Retention</span><span>Threshold</span><span>Severity</span>
                        </div>
                        {p.rules.map((r,i)=>(
                          <div key={i} style={{
                            display:"grid",gridTemplateColumns:"2fr 1fr 1fr 80px",
                            padding:"8px 12px",fontSize:12,
                            borderTop:"0.5px solid var(--color-border-tertiary)",
                            background:"var(--color-background-primary)",
                            color:"var(--color-text-primary)",
                          }}>
                            <span>{r.eventType}</span>
                            <span style={{color:"var(--color-text-secondary)"}}>{r.retention}</span>
                            <span style={{color:"var(--color-text-secondary)"}}>≥ {r.threshold}</span>
                            <SeverityBadge severity={r.severity}/>
                          </div>
                        ))}
                      </div>
                    </>
                  )}

                  {p.enforcements&&p.enforcements.length>0&&(
                    <div style={{marginTop:12}}>
                      <SectionTitle>Enforcement confirmed</SectionTitle>
                      {p.enforcements.map((e,i)=>(
                        <div key={i} style={{
                          display:"flex",alignItems:"center",gap:8,
                          padding:"6px 0",fontSize:12,color:"var(--color-text-primary)",
                          borderBottom:i<p.enforcements.length-1?"0.5px solid var(--color-border-tertiary)":"none",
                        }}>
                          <i className="ti ti-device-desktop-check" style={{color:GRN.text,fontSize:14}} aria-hidden/>
                          <code style={{fontSize:11}}>{e.aaDID}</code>
                          <span style={{color:GRY[400]}}>·</span>
                          {/* appliedCid — field added in the final PolicyRegistry */}
                          <code style={{fontSize:10,color:GRY[400]}}>{shortHash(e.appliedCid,10)}</code>
                          <span style={{color:GRY[400]}}>·</span>
                          <span style={{color:"var(--color-text-secondary)"}}>{fmt(e.confirmedAt)}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </Card>
          );
        })}
      </div>
    </div>
  );
}

/* ── PROPOSALS ────────────────────────────────────────────────────────────── */
function Proposals(){
  const [selected,setSelected]=useState(null);
  const sel=DATA.proposals.find(p=>p.proposalId===selected);

  const STEPS=["Proposed","Forwarded","Endorsed","Certified"];
  function stepIdx(status){
    const i=STEPS.indexOf(status);
    return i>=0?i:(status==="Rejected"?-1:0);
  }

  return(
    <div>
      <h1 style={{fontSize:20,fontWeight:500,margin:"0 0 20px",color:"var(--color-text-primary)"}}>
        Policy proposals
      </h1>

      <div style={{display:"grid",gridTemplateColumns:sel?"1fr 1fr":"1fr",gap:16}}>
        <div>
          {DATA.proposals.map(p=>{
            const active=selected===p.proposalId;
            const sIdx=stepIdx(p.status);
            return(
              <Card key={p.proposalId} style={{
                marginBottom:10,cursor:"pointer",
                border:`0.5px solid ${active?BLU[400]:"var(--color-border-tertiary)"}`,
                background:active?BLU[50]:"var(--color-background-primary)",
              }} onClick={()=>setSelected(active?null:p.proposalId)}>
                <div style={{display:"flex",alignItems:"flex-start",justifyContent:"space-between",marginBottom:10}}>
                  <div>
                    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:4}}>
                      <span style={{fontSize:13,fontWeight:500,color:"var(--color-text-primary)"}}>{p.domain}</span>
                      <Badge status={p.status}/>
                    </div>
                    <code style={{fontSize:10,color:"var(--color-text-secondary)"}}>{shortHash(p.proposalId)}</code>
                  </div>
                  <span style={{fontSize:11,color:"var(--color-text-secondary)"}}>{fmtShort(p.submittedAt)}</span>
                </div>

                {p.status!=="Rejected"?(
                  <div>
                    <div style={{display:"flex",alignItems:"center",gap:0,marginBottom:8}}>
                      {STEPS.map((s,i)=>{
                        const done=i<=sIdx;
                        return(
                          <div key={s} style={{display:"flex",alignItems:"center",flex:i<3?1:"auto"}}>
                            <div style={{display:"flex",flexDirection:"column",alignItems:"center",gap:2}}>
                              <div style={{
                                width:20,height:20,borderRadius:"50%",
                                background:done?BLU[400]:"var(--color-background-secondary)",
                                border:`2px solid ${done?BLU[400]:"var(--color-border-tertiary)"}`,
                                display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0,
                              }}>
                                {done&&<i className="ti ti-check" style={{color:"white",fontSize:10}} aria-hidden/>}
                              </div>
                              <span style={{fontSize:9,color:done?BLU[600]:GRY[400],whiteSpace:"nowrap"}}>{s}</span>
                            </div>
                            {i<3&&<div style={{
                              flex:1,height:2,
                              background:i<sIdx?BLU[400]:"var(--color-border-tertiary)",
                              marginBottom:14,
                            }}/>}
                          </div>
                        );
                      })}
                    </div>
                    {(p.status==="Endorsed"||p.status==="Certified")&&(
                      <div style={{display:"flex",alignItems:"center",gap:8}}>
                        <div style={{flex:1,height:4,background:GRY[100],borderRadius:2,overflow:"hidden"}}>
                          <div style={{
                            height:"100%",background:BLU[400],
                            width:`${Math.min((p.votesFor/p.quorumRequired)*100,100)}%`,borderRadius:2,
                          }}/>
                        </div>
                        <span style={{fontSize:11,color:"var(--color-text-primary)",whiteSpace:"nowrap",fontWeight:500}}>
                          {p.votesFor}/{p.quorumRequired}
                        </span>
                      </div>
                    )}
                  </div>
                ):(
                  <div style={{
                    display:"flex",alignItems:"flex-start",gap:8,
                    background:RED.bg,borderRadius:6,padding:"8px 10px",
                  }}>
                    <i className="ti ti-alert-circle" style={{color:RED.text,fontSize:14,marginTop:1,flexShrink:0}} aria-hidden/>
                    <span style={{fontSize:11,color:RED.text}}>{p.rejectReason}</span>
                  </div>
                )}
              </Card>
            );
          })}
        </div>

        {sel&&(
          <Card>
            <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:14}}>
              <div>
                <Badge status={sel.status}/>
                <div style={{fontSize:12,color:"var(--color-text-secondary)",marginTop:4}}>
                  Domain: <strong>{sel.domain}</strong>
                </div>
              </div>
              <button onClick={()=>setSelected(null)} style={{
                background:"none",border:"none",cursor:"pointer",color:GRY[400],fontSize:18,
              }}>
                <i className="ti ti-x" aria-label="Close panel"/>
              </button>
            </div>

            <Divider/>
            <SectionTitle>Delegation chain</SectionTitle>
            {[
              {label:"DEG",      value:sel.submitterDID, icon:"ti-microscope"},
              {label:"PP",       value:sel.ppDID,        icon:"ti-filter"},
              {label:"PA endorser",value:sel.endorserDID||"—",icon:"ti-shield"},
            ].map((r,i)=>(
              <div key={i} style={{display:"flex",alignItems:"center",gap:10,marginBottom:6}}>
                <i className={`ti ${r.icon}`} style={{color:BLU[400],fontSize:15,width:20,textAlign:"center"}} aria-hidden/>
                <span style={{fontSize:11,color:"var(--color-text-secondary)",width:90,flexShrink:0}}>{r.label}</span>
                <code style={{fontSize:11,color:"var(--color-text-primary)"}}>{r.value}</code>
              </div>
            ))}

            <Divider/>
            <SectionTitle>Lifecycle timestamps</SectionTitle>
            {[
              {label:"Submitted", val:sel.submittedAt},
              {label:"Forwarded",  val:sel.forwardedAt},
              {label:"Endorsed",  val:sel.endorsedAt},
              {label:"Rejected",  val:sel.rejectedAt},
            ].filter(r=>r.val).map((r,i)=>(
              <div key={i} style={{display:"flex",justifyContent:"space-between",marginBottom:4,fontSize:12}}>
                <span style={{color:"var(--color-text-secondary)"}}>{r.label}</span>
                <span style={{color:"var(--color-text-primary)"}}>{fmt(r.val)}</span>
              </div>
            ))}

            <Divider/>
            <SectionTitle>CID & references</SectionTitle>
            {[
              {label:"CID payload",       val:sel.cid},
              {label:"CID key distrib.",  val:sel.cidKeyDistrib},
              {label:"Safe default CID",  val:sel.safeDefaultCid||"—"},
              {label:"Replaces",       val:sel.replacesId&&sel.replacesId!=="0x"+"00".repeat(32)?shortHash(sel.replacesId):"— (first version)"},
            ].map((r,i)=>(
              <div key={i} style={{display:"flex",justifyContent:"space-between",marginBottom:4,fontSize:11}}>
                <span style={{color:"var(--color-text-secondary)"}}>{r.label}</span>
                <code style={{color:"var(--color-text-primary)"}}>{r.val}</code>
              </div>
            ))}

            {sel.voters.length>0&&(
              <>
                <Divider/>
                <SectionTitle>PA Votes (quorum {sel.quorumRequired}/{sel.quorumSnapshot})</SectionTitle>
                {sel.voters.map((v,i)=>(
                  <div key={i} style={{
                    display:"flex",alignItems:"center",justifyContent:"space-between",
                    padding:"5px 0",borderBottom:"0.5px solid var(--color-border-tertiary)",fontSize:12,
                  }}>
                    <code style={{fontSize:11,color:"var(--color-text-primary)"}}>{v.did}</code>
                    {v.voted
                      ? <span style={{color:v.support?GRN.text:RED.text,fontWeight:500}}>
                          {v.support?"✓ In favor":"✗ Against"}
                        </span>
                      : <span style={{color:GRY[400]}}>Pending</span>
                    }
                  </div>
                ))}
              </>
            )}
          </Card>
        )}
      </div>
    </div>
  );
}

/* ── IDENTITIES ───────────────────────────────────────────────────────────── */
function Identities(){
  const roles=["PA","PP","DEG","AUDITOR","AA","EV"];
  return(
    <div>
      <h1 style={{fontSize:20,fontWeight:500,margin:"0 0 20px",color:"var(--color-text-primary)"}}>
        Identity Registry
      </h1>

      {roles.map(role=>{
        const entities=DATA.entities.filter(e=>e.role===role);
        if(!entities.length) return null;
        const m=ROLE_META[role];
        return(
          <div key={role} style={{marginBottom:16}}>
            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
              <RoleBadge role={role}/>
              <span style={{fontSize:12,color:"var(--color-text-secondary)"}}>{m.label}</span>
              <span style={{fontSize:11,color:GRY[400]}}>· {entities.length} registered</span>
            </div>
            <Card style={{padding:0,overflow:"hidden"}}>
              <div style={{
                display:"grid",gridTemplateColumns:"2fr 1.5fr 1.5fr 1fr",
                padding:"7px 16px",background:"var(--color-background-secondary)",
                fontSize:11,color:"var(--color-text-secondary)",fontWeight:500,
                borderBottom:"0.5px solid var(--color-border-tertiary)",
              }}>
                <span>DID</span><span>Address</span><span>Registered by</span><span>Status</span>
              </div>
              {entities.map((e,i)=>(
                <div key={i} style={{
                  display:"grid",gridTemplateColumns:"2fr 1.5fr 1.5fr 1fr",
                  padding:"10px 16px",fontSize:12,
                  borderBottom:i<entities.length-1?"0.5px solid var(--color-border-tertiary)":"none",
                  background:"var(--color-background-primary)",
                  color:"var(--color-text-primary)",
                  alignItems:"center",
                }}>
                  <div>
                    <code style={{fontSize:11}}>{e.did}</code>
                    {/* pairwise — DIDType.PAIRWISE from contract, expiration required */}
                    {e.pairwise&&(
                      <span style={{
                        marginLeft:6,fontSize:9,background:AMB.bg,color:AMB.text,
                        borderRadius:4,padding:"1px 5px",
                      }}>PAIRWISE</span>
                    )}
                    {e.scope&&e.scope.length>0&&(
                      <div style={{display:"flex",gap:4,marginTop:3}}>
                        {e.scope.map(s=>(
                          <span key={s} style={{
                            fontSize:9,background:BLU[50],color:BLU[800],
                            borderRadius:4,padding:"1px 5px",
                          }}>{s}</span>
                        ))}
                      </div>
                    )}
                    {/* expiresAt — DIDDocument.expiresAt field, >0 for PAIRWISE */}
                    {e.expiresAt&&(
                      <div style={{fontSize:9,color:GRY[400],marginTop:2}}>
                        expires: {fmtShort(e.expiresAt)}
                      </div>
                    )}
                  </div>
                  <code style={{fontSize:10,color:"var(--color-text-secondary)"}}>{e.address}</code>
                  <code style={{fontSize:10,color:"var(--color-text-secondary)"}}>
                    {e.registeredBy==="genesis"
                      ? <span style={{color:BLU[600],fontFamily:"inherit"}}>genesis</span>
                      : e.registeredBy
                    }
                  </code>
                  <Badge status={e.status==="Active"?"Active":e.status}/>
                </div>
              ))}
            </Card>
          </div>
        );
      })}
    </div>
  );
}

/* ── AUDIT TRAIL ──────────────────────────────────────────────────────────── */
function AuditTrail(){
  const [typeFilter,setTypeFilter]=useState("All");
  const types=["All",...[...new Set(DATA.events.map(e=>e.type))]];
  const filtered=typeFilter==="All"?DATA.events:DATA.events.filter(e=>e.type===typeFilter);

  return(
    <div>
      <h1 style={{fontSize:20,fontWeight:500,margin:"0 0 8px",color:"var(--color-text-primary)"}}>
        Audit Trail
      </h1>
      <p style={{fontSize:13,color:"var(--color-text-secondary)",margin:"0 0 20px"}}>
        Immutable on-chain events registry · {DATA.events.length} total events
      </p>

      <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:16}}>
        {types.map(t=>{
          const m=EVENT_META[t];
          return(
            <button key={t} onClick={()=>setTypeFilter(t)} style={{
              padding:"4px 12px",borderRadius:20,border:"0.5px solid",cursor:"pointer",fontSize:11,
              background:typeFilter===t?(m?m.color:BLU[600]):"var(--color-background-primary)",
              color:typeFilter===t?"white":"var(--color-text-secondary)",
              borderColor:typeFilter===t?(m?m.color:BLU[600]):"var(--color-border-tertiary)",
            }}>{t==="All"?"All":EVENT_META[t]?.label||t}</button>
          );
        })}
      </div>

      <div style={{position:"relative"}}>
        <div style={{
          position:"absolute",left:19,top:0,bottom:0,
          width:"1px",background:"var(--color-border-tertiary)",
        }}/>
        {filtered.map((e,i)=>{
          const m=EVENT_META[e.type]||{color:GRY[400],icon:"ti-point",label:e.type};
          return(
            <div key={i} style={{display:"flex",gap:14,marginBottom:8,position:"relative"}}>
              <div style={{
                width:38,height:38,borderRadius:"50%",flexShrink:0,
                background:"var(--color-background-primary)",
                border:"0.5px solid var(--color-border-tertiary)",
                display:"flex",alignItems:"center",justifyContent:"center",
                zIndex:1,position:"relative",
              }}>
                <i className={`ti ${m.icon}`} style={{color:m.color,fontSize:16}} aria-hidden/>
              </div>
              <div style={{
                flex:1,background:"var(--color-background-primary)",
                border:"0.5px solid var(--color-border-tertiary)",
                borderRadius:8,padding:"10px 14px",
              }}>
                <div style={{
                  display:"flex",alignItems:"flex-start",justifyContent:"space-between",gap:8,marginBottom:4,
                }}>
                  <div style={{display:"flex",alignItems:"center",gap:8}}>
                    <span style={{fontSize:12,fontWeight:500,color:m.color}}>{m.label}</span>
                    <span style={{fontSize:10,color:GRY[400],fontFamily:"monospace"}}>block #{e.block}</span>
                  </div>
                  <span style={{fontSize:10,color:GRY[400],flexShrink:0,whiteSpace:"nowrap"}}>
                    {fmtShort(e.ts)}
                  </span>
                </div>
                <div style={{fontSize:12,color:"var(--color-text-primary)",marginBottom:3}}>{e.detail}</div>
                <code style={{fontSize:10,color:"var(--color-text-secondary)"}}>{e.actor}</code>
              </div>
            </div>
          );
        })}
      </div>

      {filtered.length===0&&(
        <Card style={{textAlign:"center",padding:"32px"}}>
          <span style={{color:GRY[400],fontSize:13}}>No events for the selected filter.</span>
        </Card>
      )}
    </div>
  );
}

/* ── APP ROOT ─────────────────────────────────────────────────────────────── */
export default function App(){
  const [view,setView]=useState("dashboard");
  const views={dashboard:<Dashboard/>,policies:<Policies/>,proposals:<Proposals/>,identities:<Identities/>,audit:<AuditTrail/>};

  return(
    <div style={{
      display:"flex",height:"100vh",
      fontFamily:"'SF Pro Text', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
      background:"var(--color-background-tertiary)",
      overflow:"hidden",
    }}>
      <Sidebar view={view} setView={setView}/>

      <div style={{flex:1,display:"flex",flexDirection:"column",overflow:"hidden"}}>
        <header style={{
          height:52,flexShrink:0,
          background:"var(--color-background-primary)",
          borderBottom:"0.5px solid var(--color-border-tertiary)",
          display:"flex",alignItems:"center",justifyContent:"space-between",
          padding:"0 24px",
        }}>
          <div style={{display:"flex",alignItems:"center",gap:16}}>
            <span style={{fontSize:13,color:"var(--color-text-secondary)"}}>
              University of Salerno · Blockchain Project
            </span>
          </div>
          <div style={{display:"flex",alignItems:"center",gap:16}}>
            <div style={{display:"flex",alignItems:"center",gap:6}}>
              <span style={{width:6,height:6,borderRadius:"50%",background:GRN.border,display:"inline-block"}}/>
              <span style={{fontSize:11,color:"var(--color-text-secondary)"}}>4 PA · 2 Auditor · PoA</span>
            </div>
            <div style={{
              display:"flex",alignItems:"center",gap:6,
              background:BLU[50],borderRadius:6,padding:"3px 10px",
            }}>
              <i className="ti ti-eye" style={{color:BLU[600],fontSize:13}} aria-hidden/>
              <span style={{fontSize:11,color:BLU[800],fontWeight:500}}>Audit window open</span>
            </div>
          </div>
        </header>

        <main style={{flex:1,overflow:"auto",padding:24}}>
          <h2 className="sr-only">Governance Dashboard — Logging Security Policy management system</h2>
          {views[view]||<Dashboard/>}
        </main>
      </div>
    </div>
  );
}