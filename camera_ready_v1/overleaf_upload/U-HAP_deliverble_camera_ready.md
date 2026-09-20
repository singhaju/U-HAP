\documentclass[conference]{IEEEtran}
\IEEEoverridecommandlockouts
\usepackage{cite}
\usepackage{amsmath,amssymb,amsfonts}
\usepackage{graphicx}
\usepackage{textcomp}
\usepackage{xcolor}
\usepackage{float}
\usepackage{url}
\usepackage{booktabs}
\usepackage{bbm}
\usepackage[T1]{fontenc}

\newcommand{\decs}[1]{\textnormal{\textsc{#1}}}

\begin{document}

\title{U-HAP: Unified Authorization over Heterogeneous Policies with Efficient Multi-Resource Verification in Kubernetes}

% \author{%
% \IEEEauthorblockN{Krittapak Jairak\IEEEauthorrefmark{1},
% Singha Junchan\IEEEauthorrefmark{1},
% Phisitphon Pruksorranan\IEEEauthorrefmark{1},
% Somchart Fugkeaw\IEEEauthorrefmark{1}}
% \IEEEauthorblockA{\IEEEauthorrefmark{1}School of Information,
% Computer and Communication Technology (ICT)\\
% Sirindhorn International Institute of Technology,
% Thammasat University, Thailand\\
% 6622782207@g.siit.tu.ac.th,\ 6622770350@g.siit.tu.ac.th,\
% 6622782322@g.siit.tu.ac.th,\ somchart@siit.tu.ac.th}
% }

\maketitle

%% ── Abstract ───────────────────────────────────────────────────────────────
\begin{abstract}
Kubernetes environments increasingly host multiple applications across pods
and clusters, each governed by independently defined authorization policies
such as RBAC, ABAC, and ACL\@. This heterogeneity subjects users to repeated
and fragmented authorization checks when accessing multiple resources,
resulting in increased latency, inconsistent decisions, and management
complexity. While Single Sign-On (SSO) simplifies authentication, it does not
address the challenge of unified authorization across heterogeneous policies.
We propose \textbf{U-HAP}, a unified authorization framework for efficient
and consistent multi-resource authorization across heterogeneous policies
without requiring standardization. U-HAP introduces a universal graph-based
representation that captures diverse policy models within unified semantics,
reducing authorization to a reachability problem. By compiling resource-scoped
policy artifacts and performing lightweight evaluation at request time, U-HAP
eliminates redundant checks and ensures deterministic conflict resolution. We
implement U-HAP as a Kubernetes webhook authorizer and evaluate it at scale.
Experimental results demonstrate that U-HAP maintains near-constant
authorization latency even as the number of namespaces scales, significantly
outperforming traditional approaches. Furthermore, compilation-based
optimization enables sub-linear scaling for complex policies, while decision
caching provides additional speedups for repeated requests. U-HAP further
demonstrates faster \emph{policy-update} propagation than Open Policy Agent
(OPA), completing the end-to-end edit-to-first-decision cycle significantly
faster at scale under semantically equivalent policies verified by an
automated decision-equivalence gate.
\end{abstract}
\begin{IEEEkeywords}
access control, Kubernetes, policy unification, directed acyclic graph,
hash consing, RBAC, ABAC, ACL, webhook authorization, Zero Trust
\end{IEEEkeywords}

%% ==========================================================================
\section{Introduction}
\label{sec:introduction}

Kubernetes is the de facto platform for orchestrating containerized
applications, including security-critical
systems~\cite{b1}. Yet authorization remains a major challenge:
misconfigurations and excessive permissions frequently lead to
vulnerabilities and full cluster
compromise~\cite{b2, b3}.

Authorization in Kubernetes is inherently \emph{multi-application,
multi-resource}. A single workflow may touch multiple pods, namespaces, or
clusters, each governed by independently defined policies
(RBAC~\cite{b4}, ABAC, ACL~\cite{b5}, or custom) that operate under
incompatible semantics. This results in repeated checks, inconsistent
decisions, and operational inefficiency,
even when SSO reduces authentication overhead.

Existing mechanisms suffer three key limitations:
(i)~\emph{semantic fragmentation}---RBAC, ABAC, and ACLs use incompatible
languages and semantics, increasing duplication and misconfiguration
risk~\cite{b6}; (ii)~\emph{implicit conflict resolution}---ordering across
models yields non-deterministic decisions; and (iii)~\emph{runtime
inefficiency}---repeated policy scanning evaluates irrelevant rules.
Existing solutions remain insufficient for scalable
\emph{multi-model authorization}~\cite{b7, b8}.

We propose U-HAP, a \emph{compilation-driven, index-based} framework that
shifts computation offline: policies are compiled into resource--action
scoped indices enabling a \emph{two-level pruning} strategy---\emph{policy-type
pruning} skips inactive classes, while \emph{token-driven pruning} limits
evaluation to rules matching the caller's roles and attributes. Although implemented as a Kubernetes webhook, the design is general and
applicable to other distributed environments. This paper contributes:
(i)~a unified graph-based model integrating RBAC, ABAC, ACL, and deny;
(ii)~a compilation-driven architecture eliminating runtime policy scanning;
(iii)~a lightweight two-level pruning strategy; and (iv)~a Kubernetes
webhook implementation demonstrating low-latency, deterministic
authorization with unified semantics.

%% ==========================================================================
\section{Related Work}

Security and access control in Kubernetes environments have
been widely studied, particularly from the perspectives of
system hardening and configuration correctness. Foundational
guidelines such as the NSA/CISA Kubernetes Hardening
Guidance~\cite{b1} and subsequent compliance-oriented
analyses~\cite{b9} emphasize secure control plane
configuration, workload isolation, and least-privilege
enforcement. However, empirical studies reveal that
misconfigurations and excessive permissions remain pervasive
in real-world deployments~\cite{b2, b3}, often enabling privilege
escalation and even full cluster compromise. Recent tools such
as EPScan~\cite{b10} further confirm that excessive RBAC permissions
in third-party applications continue to be a systematic security risk,
while KubeKeeper~\cite{b19} mitigates this risk via a sub-RBAC, per-pod
admission webhook for Kubernetes secrets---the same extension point
U-HAP uses, but restricted to a single resource type.
Complementary work on formal verification~\cite{b11} demonstrates that
static policy analysis can prevent misconfigurations in Kubernetes
clusters, yet such approaches address correctness of individual policies
rather than unified authorization across mixed-model environments.

Kubernetes natively adopts Role-Based Access Control
(RBAC)~\cite{b4}, which provides scalable permission
management but lacks expressiveness for fine-grained,
context-aware authorization. KubeFence~\cite{b20} addresses this by
compiling per-workload API filters at deploy time---aligned with
U-HAP's compile-then-enforce philosophy but operating at the
container-image level rather than as a unified ACL/RBAC/ABAC/Deny
authorizer. To address these limitations,
policy-as-code frameworks enable declarative and dynamic
policy enforcement, while Zero Trust
architectures~\cite{b12} promote continuous verification and
context-aware access decisions in distributed cloud-native
environments. Nevertheless, these approaches operate on
independently evaluated policy models and require repeated
evaluation across multiple enforcement layers, leading to
redundant checks and increased latency in multi-resource
authorization scenarios~\cite{b6}. Recent optimization efforts
such as PerfSPEC~\cite{b13} improve enforcement efficiency
through performance-aware profiling, and compile-time policy
optimization techniques~\cite{b14} reduce redundant rule
evaluation. However, both approaches operate within individual
policy models and do not address unified authorization across
diverse policy types.

Beyond RBAC, Attribute-Based Access Control (ABAC) and
standardized frameworks such as XACML~\cite{b7} provide more
expressive and fine-grained authorization capabilities.
However, XACML relies on heavyweight policy decision point
(PDP) architectures that are not well suited for lightweight,
low-latency cloud-native systems. Prior work on compiling XACML
policies into indexed evaluation structures~\cite{b15} has
demonstrated significant speedups over sequential evaluation,
motivating the compile-time optimization approach adopted by
U-HAP\@. Recent works explore graph-based representations
of access control, modeling authorization as relationship
inference over entities and attributes~\cite{b8, b16}.
Large-scale systems such as Zanzibar~\cite{b17} demonstrate the
scalability of relationship-based authorization, but require
runtime graph traversal, introducing overhead proportional to
graph complexity. Similarly, approaches that convert ABAC
policies into RBAC models~\cite{b18} improve interoperability
but do not resolve the challenge of unified and efficient runtime
authorization across diverse policy types.

Overall, existing works address individual aspects of Kubernetes
authorization---security hardening~\cite{b1,b9}, policy
expressiveness~\cite{b4,b7}, compile-time optimization~\cite{b14,b15},
or scalable enforcement~\cite{b17}---but none provides a unified
framework that simultaneously integrates RBAC, ABAC, ACL, and
explicit deny under a single compilation model with deterministic
runtime evaluation. U-HAP bridges this gap by treating heterogeneous
policy models as first-class citizens of a single compilation pipeline,
yielding expressive coverage, predictable O(1) per-request latency,
and scalable policy-update throughput.

%% ==========================================================================
%% FIGURE 1
\begin{figure}[htbp]
\centering
\includegraphics[width=\columnwidth]{figures/system_architecture.png}
\caption{U-HAP compilation-driven architecture on Kubernetes.}
\label{fig:arch}
\end{figure}

%% ==========================================================================
\section{Proposed System}\label{sec:design}

\subsection{System Model}

U-HAP separates \emph{policy compilation} (offline) from \emph{request-time
authorization} (online) to achieve low-latency, deterministic enforcement
(Fig.~\ref{fig:arch}).

\medskip
\noindent
\textbf{System Entities.}
\begin{itemize}
    \item \textbf{User ($\mathcal{U}$):} Authenticated subject issuing
    requests with dynamic attributes (roles, groups, context).
    \item \textbf{Administrator:} Defines policies (RBAC, ABAC, ACL, Deny)
    via the U-HAP DSL\@.
    \item \textbf{Kubernetes API Server ($\mathcal{K}$):} Dispatches
    authorization queries via \texttt{SubjectAccessReview} (SAR).
    \item \textbf{U-HAP Webhook ($\mathcal{W}$):} Evaluates SAR requests
    using compiled artifacts and returns decisions.
    \item \textbf{DSL Loader ($\mathcal{L}$):} Parses and validates
    policies.
    \item \textbf{Policy Compiler ($\mathcal{B}$):} Compiles policies into
    resource--action scoped artifacts
    $\{\mathcal{C}_{n,r,a}\}$.
    \item \textbf{Graph Registry ($\mathcal{M}$):} In-memory store for
    compiled artifacts, enabling $O(1)$ lookup.
    \item \textbf{Resources ($\mathcal{O}$):} Protected Kubernetes objects
    organized by namespace.
\end{itemize}

\medskip
\noindent
U-HAP decouples authentication from authorization by deferring user-specific
bindings to request time rather than embedding them in precomputed
structures. Identity, roles, and attributes are supplied via tokens at
request time, enabling dynamic evaluation without recompilation.

\medskip
\noindent
\textbf{Trust Assumptions.}
The API server and U-HAP components are trusted. Policies are assumed correct
after validation. Adversaries may issue malicious requests but cannot tamper
with compiled artifacts or the registry.

\subsection{Formal Graph Model}

U-HAP defines a unified graph abstraction for heterogeneous authorization
policies. For each namespace--resource pair $(n,r)$, the system constructs
\begin{equation}
G_{n,r} = (V_{n,r}, E_{n,r})
\end{equation}
where $V_{n,r}$ and $E_{n,r}$ capture all policy semantics for resource~$r$.

The vertex set $V_{n,r}$ comprises typed nodes: subject nodes
$s \in \mathcal{S}$ (authenticated identities), role nodes
$\rho \in \mathcal{R}$ (RBAC abstractions), gate nodes
$g \in \mathcal{G}$ (ABAC predicates), deny nodes $d \in \mathcal{D}$
(explicit denials), and a distinguished resource node~$r$. The edge set
$E_{n,r}$ encodes relationships: $(s,\rho)$ for subject--role assignments,
$(\rho_i,\rho_j)$ for role hierarchy, $(\rho,r)$ for role-based
permissions, $(s,r)$ for direct ACL permissions, $(s,g)$ and $(g,r)$ for
attribute-based constraints, and $(s,d)$, $(d,r)$ for explicit deny
semantics.

Well-formedness requires that (i)~the role hierarchy is acyclic,
(ii)~all edges terminate at a gate, deny, or resource node, and
(iii)~deny nodes have highest precedence, ensuring deterministic conflict
resolution.

Authorization is defined as a constrained reachability problem over
$G_{n,r}$. Given a request $(s,a,r)$ with context $\mathbf{x}$, access is
denied if a path $s \rightarrow d \rightarrow r$ exists; otherwise, access
is granted if: (i)~a direct edge $(s,r)$ exists (ACL), (ii)~a path
$s \rightarrow \rho^* \rightarrow r$ exists through the role hierarchy
(RBAC), or (iii)~a path $s \rightarrow g \rightarrow r$ exists such that
$g(\mathbf{x})$ is true (ABAC). If none apply, access is denied by default.
\subsection{System Process}
The proposed U-HAP system consists of three major phases as follows:
\subsubsection*{\textbf{Phase 1: Setup (Step-Based Description)}}

The setup phase initializes the U-HAP system and is executed once during deployment. It establishes the foundational structures required for policy compilation and runtime authorization.

\medskip
\noindent
\textbf{Step 1: System Initialization.}

Define the set of namespaces $\mathcal{N}$ and, for each $n \in \mathcal{N}$, the set of protected resources $\mathcal{O}_n$.\\
Configure the Kubernetes API server to delegate authorization decisions via \texttt{SubjectAccessReview} (SAR) requests to the U-HAP Authorization Webhook.
Normalize each incoming request into a unified representation:
\begin{equation}
\mathcal{Q}=\langle \tau,(n,r,a)\rangle
\end{equation}
where $\tau$ is the user token and $(n,r,a)$ denotes namespace, resource, and action.


\medskip
\noindent
\textbf{Step 2: Component Deployment.}
U-HAP deploys four core components: the \emph{DSL Loader}, which parses
policy definitions; the \emph{Policy Compiler/Graph Builder}, which
transforms policies into graph-based structures; the \emph{Graph Registry},
which stores compiled artifacts for constant-time lookup; and the
\emph{Authorization Webhook}, which handles runtime authorization requests.
The DSL Loader and Compiler operate offline during policy preparation,
while the Registry and Webhook serve the runtime authorization path.

\medskip
\noindent
\textbf{Step 3: State Initialization.}
The system initializes both a \emph{persistent policy store} (e.g.,
Kubernetes ConfigMaps) to maintain policy definitions and an
\emph{in-memory registry} to enable efficient runtime access. For each
$(n,r,a)$, a structured container of compiled artifacts is allocated as
\begin{equation}
\mathcal{C}_{n,r,a}=
\left(
G_{n,r},\,
I^{\mathit{acl}}_{n,r,a},\,
I^{\mathit{rbac}}_{n,r,a},\,
I^{\mathit{abac}}_{n,r,a},\,
I^{\mathit{attr}}_{n,r,a},\,
I^{\mathit{deny}}_{n,r,a},\,
\Psi_{n,r,a}
\right),
\end{equation}
where each component corresponds to a graph structure, policy index, or
auxiliary metadata as defined in Table~\ref{tab:artifacts}.

\medskip
\noindent
\textbf{Step 4: Token Trust Configuration.}

Define the authenticated user token structure as:
\begin{equation}
\tau=
\langle
uid,\,
\mathcal{R}_u,\,
\mathcal{G}_u,\,
\mathcal{A}_u,\,
t_{\mathrm{exp}},\,
\sigma
\rangle
\end{equation}
Where $uid,\mathcal{R}_u,\mathcal{G}_u,\mathcal{A}_u,t_{exp},\sigma$ denote the authenticated user identity, the role set, the group set, the user attributes, the token expiration, and the cryptographic signature, respectively.
Assume token authenticity is verified prior to authorization (e.g., via Kubernetes authentication layer).
Define the supported policy types:
\[
\Pi_n=\{\texttt{RBAC},\texttt{ABAC},\texttt{ACL},\texttt{Deny}\}
\]
with enforced schema and validation constraints.

\medskip
\noindent


\subsubsection*{\textbf{Phase 2: Policy Compilation}}

The compilation phase transforms DSL policies into
\emph{resource--action-scoped runtime artifacts} consumed by the verifier in
Phase~3. Rather than relying on runtime graph traversal, U-HAP compiles
policies into verification-oriented indices enabling constant-time lookup,
token-driven pruning, and short-circuit evaluation.

\medskip
\noindent
\textbf{Input and Output.}
For
$\Pi_n=\{\texttt{RBAC},\texttt{ABAC},\texttt{ACL},\texttt{Deny}\}$,
the compiler produces:
\begin{equation}
\mathcal{C}_n=
\left\{
\mathcal{C}_{n,r,a}
\mid r \in \mathcal{O}_n,\ a \in \mathbb{A}
\right\}
\end{equation}
where each unit $\mathcal{C}_{n,r,a}$ aligns with the verification input
$\langle \tau,(n,r,a)\rangle$, eliminating runtime filtering. 

\medskip
\noindent
\textbf{Compilation Procedure.}

\noindent
\textbf{Step~1: Ingestion and IR Construction.}
Policies are parsed into:
\begin{equation}
\mathcal{IR}=(\mathcal{S},\mathcal{R},\mathcal{P},\mathbb{A},\mathcal{D})
\end{equation}
Where $\mathcal{S},\mathcal{R}, \mathcal{P}, \mathbb{A},\mathcal{D}$
denote the sets of subjects, roles, permissions, actions, and deny rules, respectively.\\
\noindent
\textbf{Step~2: Validation and Normalization.}
The DSL Loader enforces syntax, type safety, reference consistency, and
acyclic role hierarchies. Role inheritance is reduced to transitive closure
$\rho_i \Rightarrow^* \rho_j$.

\noindent
\textbf{Step~3: Resource--Action Decomposition.}
Policies are partitioned as $\Pi_n \rightarrow \{\Pi_{n,r,a}\}$, ensuring
each artifact corresponds exactly to $(n,r,a)$.

\noindent
\textbf{Step~4: Artifact Generation.}
For each $(n,r,a)$, the artifacts shown in Table~\ref{tab:artifacts} are
constructed.

\begin{table}[H]
\centering
\caption{Compiled artifacts per resource--action scope $(n,r,a)$.}
\label{tab:artifacts}
\setlength{\tabcolsep}{3pt}
\renewcommand{\arraystretch}{1.4}
\begin{tabular}{lll}
\toprule
\textbf{Artifact} & \textbf{Definition} & \textbf{Notes} \\
\midrule
Graph
& $G_{n,r}$
& audit only \\
Deny
& $I^{\mathit{deny}}_{n,r,a} = \{(\mathrm{scope}(d), \phi_d)\}$
& constant-time match \\
ACL
& $I^{\mathit{acl}}_{n,r,a} = \mathcal{S}^{\mathit{acl}}_{r,a}$
& membership check \\
RBAC
& $I^{\mathit{rbac}}_{n,r,a} = \{\rho \mid \rho \Rightarrow^* (r,a)\}$
& $\mathcal{R}_u \cap I^{\mathit{rbac}}_{n,r,a} \neq \emptyset$ \\
ABAC
& $I^{\mathit{abac}}_{n,r,a} = \{(g_\phi, \mathrm{req}(\phi))\}$
& $g_\phi : \mathcal{A}_u \to \{0,1\}$ \\
Attr
& $I^{\mathit{attr}}_{n,r,a} : k \mapsto \{\phi \mid k \in \mathrm{req}(\phi)\}$
& selective evaluation \\
Summary
& $\Psi_{n,r,a} =\langle\mathcal{S}^{\mathit{acl}}_{r,a},\mathcal{R}^{\mathit{rbac}}_{r,a},
  \Phi^{\mathit{abac}}_{r,a}, \mathcal{D}_{r,a}\rangle$
& -- \\
\bottomrule
\end{tabular}
\end{table}
where $\mathrm{scope}(d)$ is the set of principals to which deny rule 
$d$ applies, $\phi_d$ is the condition predicate of deny rule $d$, and 
$\mathrm{req}(\phi)$ is the set of attribute keys required by predicate 
$\phi$.

\noindent
Each ABAC predicate $\phi$ is compiled into a DAG of \texttt{GateNode}
objects via \emph{hash consing}: structurally identical sub-expressions
across policies share a single node, so any predicate appearing in $k$
policies maps to exactly one \texttt{GateNode} in the shared DAG\@.

\noindent
\textbf{Step~5: Finalization and Registration.}
Redundant edges are removed, unreachable nodes are pruned, and consistency
is verified. All $\mathcal{C}_{n,r,a}$ are then stored in the Graph
Registry for $O(1)$ retrieval. ACL reduces to membership checking, RBAC to
set intersection, ABAC to attribute-key--pruned predicate evaluation, and
deny to prioritized filtering, eliminating global policy scans at runtime.

\subsubsection*{\textbf{Phase 3: Request-Time Authorization}}

At runtime, U-HAP evaluates each request using a
\emph{policy-type-pruned, token-projected, index-optimized} pipeline over
the compiled artifacts generated in Phase~2 and summarized in
Table~\ref{tab:artifacts}. Given a request
$\mathcal{Q}=\langle \tau,(n,r,a)\rangle$, the goal is to determine whether
the user represented by token $\tau$ is authorized to perform action $a$ on
resource $r$ in namespace $n$.

\medskip
\noindent
\textbf{Step 1: Request Reception and Token Extraction.}
The Authorization Webhook receives
$\mathcal{Q}=\langle \tau,(n,r,a)\rangle$, where the validated token is
\begin{equation}
\tau=\langle uid,\mathcal{R}_u,\mathcal{G}_u,\mathcal{A}_u,t_{\mathrm{exp}},\sigma\rangle .
\end{equation}
Here, $uid$ denotes the authenticated user identity,
$\mathcal{R}_u$ the role set, $\mathcal{G}_u$ the group set, and
$\mathcal{A}_u$ the user and contextual attributes. 

\medskip
\noindent
\textbf{Step 2: Constant-Time Artifact Retrieval.}
Using the tuple $(n,r,a)$ as a lookup key, the Webhook retrieves the
compiled container $\mathcal{C}_{n,r,a}$ from the registry in $O(1)$ time.
This container includes the graph, policy indices, and metadata defined in
Table~\ref{tab:artifacts}. It also provides the fast-path activation
descriptor
\begin{equation}
\Xi_{n,r,a}=
\langle
\lambda^{\mathit{deny}},\lambda^{\mathit{acl}},
\lambda^{\mathit{rbac}},\lambda^{\mathit{abac}}
\rangle ,
\end{equation}
where each bit $\lambda^{*}\in\{0,1\}$ indicates whether the corresponding
policy type has at least one compiled rule for the requested
$(n,r,a)$. Any class with $\lambda=0$ is skipped entirely.

\medskip
\noindent
\textbf{Step 3: Candidate Pruning.}
To avoid scanning irrelevant rules, U-HAP prunes the search space in two
stages. First, \emph{policy-type pruning} uses $\Xi_{n,r,a}$ to eliminate
inactive policy classes. Second, \emph{token-driven pruning} derives only
the candidates relevant to the current user token:
\begin{align}
\Gamma_{\mathrm{deny}} &=
\{d \mid \mathrm{scope}(d)\cap(\{uid\}\cup\mathcal{G}_u\cup\mathcal{R}_u)\neq\emptyset\},\\
\Gamma_{\mathrm{acl}} &=
(\{uid\}\cup\mathcal{G}_u)\cap I^{\mathit{acl}}_{n,r,a},\\
\Gamma_{\mathrm{rbac}} &=
\mathcal{R}_u \cap I^{\mathit{rbac}}_{n,r,a},\\
\Gamma_{\mathrm{abac}} &=
\bigcup_{k\in\mathrm{dom}(\mathcal{A}_u)} I^{\mathit{attr}}_{n,r,a}(k).
\end{align}
Thus, Phase~3 evaluates only a compact request-specific subset rather than
the full policy set.

\medskip
\noindent
\textbf{Step 4: Decision Cache Check.}
Before evaluating rules, U-HAP checks a short-lived cache keyed by
\begin{equation}
\kappa = H(uid,n,r,a,\mathbf{b}_u,\mathbf{g}_u,\mathrm{sig}(\mathcal{A}_u)),
\end{equation}
where $\mathbf{b}_u$ and $\mathbf{g}_u$ are compact bit-vector encodings 
of user role and group memberships, $H(\cdot)$ is a collision-resistant 
hash function mapping the tuple to a $\kappa$, and 
$\mathrm{sig}(\mathcal{A}_u)$ is a deterministic digest over the user 
attribute map $\mathcal{A}_u$. 
Thus, if $\kappa$ is found in the cache, the system immediately returns the cached decision (e.g., allow) without further evaluation.
%if $\kappa$ is present, the cached decision is returned immediately.

\medskip
\noindent
\textbf{Step 5: Ordered Policy Verification.}  
On a cache miss, U-HAP evaluates policies in fixed order
$\text{Deny}\!\to\!\text{ACL}\!\to\!\text{RBAC}\!\to\!\text{ABAC}\!\to\!\text{Default Deny}$,
terminating upon a definitive decision.

\smallskip
\noindent
\emph{(a) Deny Check.}  
Deny rules take precedence. If any matches, the request is rejected:
\begin{equation}
\exists\, d\in\Gamma_{\mathrm{deny}}:
\mathrm{match}_{\mathit{deny}}(d,\tau,n,r,a)=1
\;\Rightarrow\; \decs{Deny},
\end{equation}
where $\mathrm{match}_{\mathit{deny}}=1$ iff $uid \in \mathrm{scope}(d)$ and $\phi_d(\tau,n,r,a)=1$.
This evaluation order enforces a \emph{monotone safety property}: no
subsequent ACL, RBAC, or ABAC allow rule can override an explicit deny,
providing a formal guarantee against privilege escalation via
policy interaction.

\smallskip
\noindent
\emph{(b) ACL Check.}  
If no deny applies, ACL authorization is checked via constant-time hash membership:
\begin{equation}
uid \in I^{\mathit{acl}}_{n,r,a}
\;\lor\;
\mathcal{G}_u \cap I^{\mathit{acl}}_{n,r,a}\neq\emptyset.
\end{equation}
If true, the request is allowed.

\smallskip
\noindent
\emph{(c) RBAC Check.}  
RBAC is evaluated using precompiled bit-vectors for efficient role matching. 
Let $\mathbf{b}_u$ encode the roles in $\mathcal{R}_u$, and let 
$\mathbf{b}^{\mathit{rbac}}_{n,r,a}$ denote the authorized-role bit-vector 
for $(n,r,a)$ after applying transitive closure over the role hierarchy. 
Authorization holds iff:
\begin{equation}
\mathbf{b}_u \wedge \mathbf{b}^{\mathit{rbac}}_{n,r,a} \neq \mathbf{0}.
\end{equation}
This constant-time bitwise operation eliminates the need for runtime 
role-hierarchy traversal and ensures scalable authorization.

\smallskip
\noindent
\emph{(d) ABAC Check.}  
If RBAC fails, only relevant ABAC predicates are evaluated, sorted by cost:
\begin{equation}
\Gamma_{\mathrm{abac}}^{\uparrow}
=
\mathrm{sort}(\Gamma_{\mathrm{abac}},\mathrm{cost}).
\end{equation}
Authorization holds if any predicate succeeds:
\begin{equation}
\exists\, \phi\in\Gamma_{\mathrm{abac}}^{\uparrow}:
g_\phi(\mathcal{A}_u)=1
\;\Rightarrow\; \decs{Allow}.
\end{equation}
Composite predicates are:
\begin{align}
g_{\phi_1\land\phi_2} &= g_{\phi_1}\wedge g_{\phi_2},\quad
g_{\phi_1\lor\phi_2} = g_{\phi_1}\vee g_{\phi_2},\\
g_{\mathrm{th}(k,\{\phi_i\})} &= \mathbbm{1}\!\left[\sum_i g_{\phi_i}\ge k\right].
\end{align}

\medskip
\noindent
\textbf{Step 6: Default and Cache Update.}  

$\mathsf{Verify}(\tau,n,r,a)$ returns a cached decision on hit. Otherwise, it applies the above order: Deny $\rightarrow$ Allow (ACL/RBAC/ABAC) $\rightarrow$ Default Deny, and caches the result under $\kappa$.

\smallskip
\noindent
\textbf{Runtime Complexity.}
Artifact retrieval is $O(1)$ by hash-keyed registry. ACL membership is
$O(1)$ via hash set; RBAC is $O(1)$ via bitwise AND; ABAC is $O(|\mathrm{gates}|)$ with
per-node memoization guaranteeing each gate is evaluated at most once per
request; deny pruning is $O(|\Gamma_{\mathrm{deny}}|)$, bounded by applicable
rules. Combined with the decision cache, Phase~3 is worst-case
$O(|\mathrm{gates}|)$ and typically $O(1)$ on warm requests---independent
of total policy-set size or namespace count.

%% ==========================================================================
\section{Experimental Evaluation}\label{sec:eval}

We evaluate U-HAP (Python~3.11) on an AMD Ryzen~9 7945HX (16C/32T),
32\,GB DDR5-4800, CachyOS Linux. We compare against a conventional
\emph{SSO-based baseline} in which access rights are verified by
evaluating application-specific policies stored in the cluster.
Each data point is the median of 1{,}000 single-threaded iterations
after 50 warm-ups, measuring only in-memory policy lookup and
verification (no network or auth overhead). Each \emph{namespace}
models an independent application or workload.

\textbf{Experiment 1 (Policy Verification Efficiency).}
We compare U-HAP, U-HAP with caching, and a conventional SSO baseline
as the number of namespaces $N\!\in\!\{10,50,100,200,300,500,750,1000\}$
grows. Each namespace contains 46 rules (10~RBAC, 20~ABAC, 10~ACL,
1~deny, 5~hierarchy edges); ABAC predicates use 10 logical gates
(AND/OR/ATLEAST) and 11 attributes from a 20-key pool, with ${\sim}50\%$
atom sharing across rules.

\begin{figure}[htbp]
\centering
\includegraphics[width=\columnwidth]{figures/fig2_namespace_isolation.png}
\caption{Per-request authorization latency vs.\ total number of
  application namespaces.}
\label{fig:namespace}
\end{figure}
Fig.~\ref{fig:namespace} shows near-constant latency for all
configurations as $N$ scales from 10 to 1{,}000: namespace growth does
not affect the verification cost of any target. U-HAP achieves
${\approx}1.7\times$ lower latency than the baseline via compiled
evaluation (shared ABAC DAG, hash-set ACL, bit-vector RBAC), while
caching provides an additional ${\sim}14\times$ speedup on repeated
requests by bypassing evaluation entirely.
In contrast, the SSO baseline performs sequential policy
scanning---including repeated role resolution and hierarchy traversal
for RBAC---whose cost scales linearly with namespace count,
explaining its proportionally higher and less predictable latency.

\textbf{Experiment 2 (Policy Size Impact).}
We vary $k\!\in\![5,320]$ rules per model (one model type per namespace).
ABAC predicates use 10 gates with 50\% atom sharing; the matching rule
sits at the median position so the baseline scans ${\sim}k/2$ rules.
Caching is disabled to expose raw evaluation cost.

\begin{figure}[htbp]
\centering
\includegraphics[width=\columnwidth]{figures/fig3_permodel_latency.png}
\caption{Per-model authorization latency (log scale) vs.\ number of
  rules ($k{=}5$--$320$).}
\label{fig:permodel}
\end{figure}

Fig.~\ref{fig:permodel} shows compilation gains increase with $k$.
ABAC benefits most: hash-consed DAG evaluation yields up to $16.9\times$
speedup at $k{=}320$ (crossover $k{\approx}20$; minor $0.7\times$ overhead
at $k{=}5$). ACL and RBAC remain near-constant via hash-set and
bit-vector evaluation, reaching $5.0\times$ and $5.6\times$ at $k{=}320$.
Overall, compilation overhead at very small $k$ is marginal and quickly
amortized; performance gains become significant beyond the crossover point
and grow monotonically with rule-set scale.

\textbf{Experiment 3 (Policy Update Latency vs.\ OPA).}
We measure end-to-end \emph{update latency} (policy edit to first
decision under the new policy) against \textbf{OPA}~\cite{b21}, the CNCF
graduated general-purpose engine. Each U-HAP policy set is mechanically
translated to equivalent Rego; an automated gate confirms $100/100$
identical decisions at every $n\!\in\![10,2000]$. Policy sets
($n\!\in\!\{10,100,500,1000,2000\}$, fixed mix: $40\%$ RBAC, $30\%$
ABAC, $15\%$ ACL, $10\%$ deny, $5\%$ hierarchy) run $30$ timed updates
per $n$ after $3$ warm-ups; we report medians with $95\%$ bootstrap CIs
and additionally post-parse (engine-only) latency, since YAML parsing is
a fixed cost both engines pay.

\begin{figure}[htbp]
\centering
\includegraphics[width=\columnwidth]{figures/fig5_update_latency.png}
\caption{End-to-end update latency vs.\ policy count (log--log).
Bars are $95\%$ percentile-bootstrap CIs.}
\label{fig:exp5}
\end{figure}

\begin{table}[htbp]
\caption{Update latency medians (ms). Post-parse excludes YAML parse (engine-agnostic cost). Speedup = OPA / U-HAP.}
\label{tab:exp5}
\centering
\small
\setlength{\tabcolsep}{4pt}
\begin{tabular}{rrrrrrr}
\toprule
& \multicolumn{3}{c}{Total\,(ms)} & \multicolumn{3}{c}{Post-parse\,(ms)} \\
\cmidrule(lr){2-4}\cmidrule(lr){5-7}
$n$ & U-HAP & OPA & $\times$ & U-HAP & OPA & $\times$ \\
\midrule
10   &   1.75 &   2.85 & $1.63\times$ &  0.14 &   2.85 & $20.4\times$ \\
100  &  14.76 &  26.60 & $1.80\times$ &  2.03 &  26.60 & $13.1\times$ \\
500  &  57.35 & 119.40 & $2.08\times$ &  7.87 & 119.40 & $15.2\times$ \\
1000 & 109.99 & 277.32 & $2.52\times$ & 16.27 & 277.32 & $17.0\times$ \\
2000 & 223.41 & 610.54 & $2.73\times$ & 31.31 & 610.54 & $19.5\times$ \\
\bottomrule
\end{tabular}
\end{table}

As shown in Table~\ref{tab:exp5} and Fig.~\ref{fig:exp5}, U-HAP
completes the update cycle faster at every $n$, from $1.63\times$ at
$n{=}10$ to $2.73\times$ at $n{=}2000$. The post-parse advantage grows
to $19.5\times$ at $n{=}2000$ ($31$\,ms vs.\ $611$\,ms), demonstrating
the asymptotic benefit of compile-time hash consing over OPA's
per-update Rego compilation. An OPA bundle-activation mode lands within
$\pm 4\%$ of REST PUT, ruling out a deployment-mode artefact. The
compiled-state footprint stays ${\le}2.7$\,MiB throughout.

%% ==========================================================================
\section{Conclusion}

This paper presented U-HAP, a compilation-driven authorization framework that unifies RBAC, ABAC, ACL, and explicit deny into a single,
consistent mechanism for Kubernetes. By shifting policy reasoning to an
offline compilation phase, U-HAP eliminates redundant runtime scanning
and enables efficient authorization through indexed artifacts and
lightweight verification. Experimental results show that U-HAP achieves stable, low latency as the
number of namespaces scales, outperforming conventional SSO-based
approaches that rely on repeated policy evaluation. Compilation and
decision caching provide complementary gains, achieving approximately
$1.7\times$ speedup from compiled evaluation and up to $14\times$ for
repeated requests. Per-model analysis further demonstrates improved
efficiency across all policy types, with up to $16.9\times$ speedup for
ABAC, $5.0\times$ for ACL, and $5.6\times$ for RBAC at $k{=}320$ rules.
Beyond the request path, U-HAP also outperforms OPA on the
\emph{policy-update} path: at $2{,}000$ rules it completes the full
edit-to-first-decision cycle in $223$\,ms versus OPA's $611$\,ms
($2.73\times$ end-to-end, $19.5\times$ post-parse) with a $2.7$\,MiB
compiled-state footprint.
The combination of compile-time transitive role closure, hash-consed
ABAC DAGs, and token-projected index pruning constitutes a principled
optimization strategy: structural sharing eliminates redundant predicate
evaluation, role reachability is resolved once offline, and every
runtime path reduces to a bounded sequence of hash-set lookups and
bitwise operations---properties that generalize to any distributed
authorization service reconciling heterogeneous policy models at scale.
Future work includes extending U-HAP to support cluster-wide and
cross-namespace policies, enabling dynamic updates without full
recompilation, and integrating with production-grade authorization
engines for large-scale multi-cluster evaluation.

%% ==========================================================================
\begin{thebibliography}{21}
\bibitem{b1}
{NSA and CISA},
``Kubernetes Hardening Guidance,''
NSA Cybersec.\ Tech.\ Report, ver.~1.2, Aug.\ 2022.
[Online]. Available: \url{https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF}

\bibitem{b2}
A.~Rahman, S.~I.~Shamim, D.~B.~Bose, and R.~Pandita,
``Security Misconfigurations in Open Source Kubernetes Manifests:
An Empirical Study,''
\emph{ACM Trans.\ Softw.\ Eng.\ Methodol.}, vol.~32, no.~4, 2023, doi: 10.1145/3579639.

\bibitem{b3}
N.~Yang, W.~Shen, J.~Li, X.~Liu, X.~Guo, and J.~Ma,
``Take Over the Whole Cluster: Attacking Kubernetes via Excessive
Permissions of Third-Party Applications,''
in \emph{Proc.\ ACM CCS}, 2023, pp.~3048--3062.

\bibitem{b4}
G.~Rostami,
``Role-Based Access Control ({RBAC}) Authorization in Kubernetes,''
\emph{J.\ ICT Standardization}, vol.~11, no.~3, pp.~237--260, 2023,
doi: 10.13052/jicts2245-800X.1132.

\bibitem{b5}
N.~Farhadighalati, L.~A.~Estrada-Jimenez, S.~Nikghadam-Hojjati, and J.~Barata,
``A Systematic Review of Access Control Models: Background, Existing Research,
and Challenges,''
\emph{IEEE Access}, vol.~13, pp.~17777--17806, 2025,
doi: 10.1109/ACCESS.2025.3533145.

\bibitem{b6}
M.~S.~Rahaman, S.~N.~Tisha, E.~Song, and T.~Cerny,
``Access Control Design Practice and Solutions in Cloud-Native Architecture: A Systematic Mapping Study,''
\emph{Sensors}, vol.~23, no.~7, art.\,no.\,3413, 2023.

\bibitem{b7}
{OASIS},
``{eXtensible Access Control Markup Language (XACML)} Version~3.0
Plus Errata~01,''
OASIS Standard, 2017.

\bibitem{b8}
M.~Yang, V.~Atluri, S.~Sural, and J.~Vaidya,
``A Graph-Based Framework for {ABAC} Policy Enforcement and
Analysis,''
in \emph{Proc.\ DBSec}, 2024, pp.~3--23.

\bibitem{b9}
Z.~Mori\'{c}, V.~Daki\'{c}, and T.~\v{C}avala,
``Security Hardening and Compliance Assessment of Kubernetes Control
Plane and Workloads,''
\emph{J.\ Cybersec.\ Privacy}, vol.~5, no.~2, art.\,no.\,30, 2025.

\bibitem{b10}
Y.~Gu, X.~Tan, Y.~Zhang, S.~Gao, and M.~Yang,
``EPScan: Automated Detection of Excessive RBAC Permissions in Kubernetes Applications,''
in \emph{Proc.\ 2025 IEEE Symp.\ Security and Privacy (SP)}, 2025, pp.~3199--3217.

\bibitem{b11}
A.~Sissodiya, E.~Chiquito, U.~Bodin, and J.~Kristiansson,
``Formal Verification for Preventing Misconfigured Access Policies
in {Kubernetes} Clusters,''
\emph{IEEE Access}, vol.~13, pp.~141798--141813, 2025, doi: 10.1109/ACCESS.2025.3597504.

\bibitem{b12}
R.~Chandramouli and Z.~Butcher,
``A Zero Trust Architecture Model for Access Control in Cloud-Native
Applications in Multi-Location Environments,''
NIST SP 800-207A, 2023.

\bibitem{b13}
H.~Nguyen \emph{et~al.},
``{PerfSPEC}: Performance Profiling-Based Proactive Security Policy
Enforcement for Containers,''
\emph{IEEE Computer}, 2025.

\bibitem{b14}
S.~Kern, T.~Baumer, S.~Groll, L.~Fuchs, and G.~Pernul,
``Optimization of Access Control Policies,''
\emph{J.\ Inf.\ Secur.\ Appl.}, vol.~70, art.\,no.\,103301, 2022.

\bibitem{b15}
A.~X.~Liu, F.~Chen, J.~Hwang, and T.~Xie,
``Designing Fast and Scalable XACML Policy Evaluation Engines,''
\emph{IEEE Trans.\ Computers}, vol.~60, no.~12, pp.~1802--1817, Dec.\ 2011.

\bibitem{b16}
L.~Ma \emph{et~al.},
``Research on Authorization Model of Attribute Access Control Based
on Knowledge Graph,''
in \emph{Proc.\ UbiSec}, Springer, 2024, pp.~350--364.

\bibitem{b17}
R.~Pang, R.~Caceres, M.~Burrows, \emph{et~al.},
``Zanzibar: {Google's} Consistent, Global Authorization System,''
in \emph{Proc.\ USENIX ATC}, 2019, pp.~33--46.

\bibitem{b18}
M.~Davari and M.~Zulkernine,
``Automatic Conversion of ABAC Policies for RBAC Systems,''
in \emph{Proc.\ 2023 IEEE Conf.\ Dependable and Secure Computing (DSC)}, 2023, pp.~1--7, doi: 10.1109/DSC61021.2023.10354157.

\bibitem{b19}
M.~Rostamipoor, S.~Sadeghi, and M.~Polychronakis,
``KubeKeeper: Protecting {K}ubernetes Secrets Against Excessive Permissions,''
in \emph{Proc.\ 2025 IEEE Eur.\ Symp.\ Security and Privacy (EuroS\&P)}, 2025, pp.~322--338.

\bibitem{b20}
C.~Cesarano and R.~Natella,
``KubeFence: Security Hardening of the {K}ubernetes Attack Surface,''
in \emph{Proc.\ 2025 IEEE/IFIP Int.\ Conf.\ on Dependable Systems and Networks (DSN)}, 2025, pp.~497--510, doi: 10.1109/DSN64029.2025.00054.

\bibitem{b21}
{Open Policy Agent},
``OPA --- Open Policy Agent,'' CNCF graduated project, 2024.
[Online]. Available: \url{https://www.openpolicyagent.org/}

\end{thebibliography}
\end{document}
