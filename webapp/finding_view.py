"""One validated filter/order definition for finding lists and their detail navigation."""
SORTS = {
    "sequence": "id", "id": "rule_id COLLATE NOCASE", "owasp": "CAST(SUBSTR(owasp,4) AS INTEGER)",
    "severity": "CASE LOWER(severity) WHEN 'low' THEN 1 WHEN 'medium' THEN 2 WHEN 'high' THEN 3 WHEN 'critical' THEN 4 ELSE 0 END",
    "verdict": "CASE verdict WHEN 'INFO' THEN 0 WHEN 'PASS' THEN 1 WHEN 'ERROR' THEN 2 WHEN 'REVIEW' THEN 3 WHEN 'FAIL' THEN 4 ELSE -1 END",
    "triage": "CASE WHEN verdict != 'FAIL' THEN 0 WHEN triage_status='false_positive' THEN 1 WHEN triage_status='accepted_risk' THEN 2 ELSE 3 END",
    "confidence": "confidence",
}
VERDICTS = ("FAIL", "REVIEW", "ERROR", "PASS", "INFO")
ENGINE_SQL = "CASE WHEN source IN ('cgllm_research','public_research','community_sourced','community','custom_ui','custom','base','static','rules') THEN 'static' ELSE COALESCE(source,'other') END"
ENGINE_LABELS = {"static":"Static", "ai_agent":"AI-Powered", "garak":"Garak", "pyrit":"PyRIT",
                 "crescendo":"Crescendo", "ai_recon":"AI Recon", "canary":"Canary", "fingerprint":"Fingerprint",
                 "session_isolation":"Session isolation", "chaining":"Attack chains", "scanner":"Scanner", "other":"Other"}


class FindingView:
    def __init__(self, conn, result_id, args):
        self.result_id = result_id
        self.engines = [r[0] for r in conn.execute("SELECT DISTINCT " + ENGINE_SQL + " AS engine FROM findings WHERE scan_result_id=? ORDER BY engine",(result_id,))]
        self.categories = [r[0] for r in conn.execute("SELECT DISTINCT owasp FROM findings WHERE scan_result_id=? AND owasp IS NOT NULL ORDER BY owasp",(result_id,))]
        self.sort = args.get("sort", "sequence")
        if self.sort not in SORTS:self.sort = "sequence"
        self.direction = args.get("direction", "asc").lower()
        if self.direction not in ("asc", "desc"):self.direction = "asc"
        self.verdict = args.get("verdict", "all").upper()
        if self.verdict not in VERDICTS:self.verdict = "all"
        self.engine = args.get("engine", "all")
        if self.engine not in self.engines:self.engine = "all"
        self.category = args.get("category", "all")
        if self.category not in self.categories:self.category = "all"
        self.query = args.get("q", "").strip()
        try:self.page = max(1,int(args.get("page",1)))
        except (ValueError,TypeError):self.page = 1
        self.order = ("(confidence IS NULL) ASC, " if self.sort == "confidence" else "") + SORTS[self.sort] + " " + self.direction.upper() + ", id ASC"

    def where(self, omit_verdict=False):
        conditions,values = ["scan_result_id=?"],[self.result_id]
        if self.verdict != "all" and not omit_verdict:
            conditions.append("verdict=?");values.append(self.verdict)
        if self.engine != "all":
            conditions.append(ENGINE_SQL + "=?");values.append(self.engine)
        if self.category != "all":
            conditions.append("owasp=?");values.append(self.category)
        if self.query:
            conditions.append("instr(lower(COALESCE(rule_id,'')||' '||COALESCE(module,'')||' '||COALESCE(description,'')||' '||COALESCE(prompt_sent,'')||' '||COALESCE(raw_response,'')),lower(?))>0")
            values.append(self.query)
        return " AND ".join("("+c+")" for c in conditions),values

    def params(self, **changes):
        values={"sort":self.sort,"direction":self.direction,"verdict":self.verdict,"engine":self.engine,
                "category":self.category,"q":self.query,"page":self.page}
        values.update(changes)
        return {k:v for k,v in values.items() if v not in ("",None)}

    def count(self,conn):
        where,values=self.where()
        return conn.execute("SELECT COUNT(*) FROM findings WHERE "+where,values).fetchone()[0]

    def counts(self,conn):
        where,values=self.where(omit_verdict=True)
        counts={r["verdict"]:r["n"] for r in conn.execute("SELECT verdict,COUNT(*) AS n FROM findings WHERE "+where+" GROUP BY verdict",values)}
        return {"all":sum(counts.values()),**{v:counts.get(v,0) for v in VERDICTS}}

    def navigation(self,conn,finding_id):
        where,values=self.where()
        sql=("WITH ordered AS (SELECT id,ROW_NUMBER() OVER w AS position,COUNT(*) OVER() AS total,"
             "LAG(id) OVER w AS previous_id,LEAD(id) OVER w AS next_id FROM findings WHERE "+where+
             " WINDOW w AS (ORDER BY "+self.order+")) SELECT * FROM ordered WHERE id=?")
        row=conn.execute(sql,values+[finding_id]).fetchone()
        return dict(row) if row else None
