package com.sast.engine.taint;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.sast.engine.rules.SecurityRule;
import com.sast.model.Finding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Taint Analysis Engine — Source → Propagator → Sink 흐름 탐지
 *
 * 알고리즘: 인트라-프로시저럴 Dataflow (메서드 단위)
 *   - IV-1.1 SQL 삽입 (CWE-89)
 *   - IV-1.3 경로 조작 (CWE-22)
 *   - IV-1.4 XSS (CWE-79)
 *   - IV-1.5 OS 명령어 삽입 (CWE-78)
 *   - 그 외 taintAnalysis: true 규칙 전체
 */
public class TaintAnalysisEngine {

    private static final Logger log = LoggerFactory.getLogger(TaintAnalysisEngine.class);

    // ── Source Signatures ────────────────────────────────────────────────

    private static final Set<String> SOURCE_METHODS = new HashSet<>(Arrays.asList(
            "getParameter", "getAttribute", "getQueryString",
            "getHeader", "getCookies", "getInputStream", "getReader",
            "getenv", "getProperty",
            "readLine", "readAllBytes",
            "readObject", "readUnshared"
    ));

    // ── Sanitizer Signatures ─────────────────────────────────────────────

    private static final Set<String> SANITIZER_METHODS = new HashSet<>(Arrays.asList(
            "prepareStatement", "setString", "setInt", "setLong", "setObject",
            "setParameter", "escapeSQL",
            "escapeHtml", "encodeForHTML", "htmlEscape", "encodeHTML",
            "getCanonicalPath", "normalize",
            "encodeForLDAP", "encodeForXPath", "encodeForHTTP",
            "encode", "canonicalize"
    ));

    // ── Sink Signatures (Rule별 매핑) ─────────────────────────────────────

    private static final Map<String, Set<String>> RULE_SINKS;
    static {
        Map<String, Set<String>> m = new HashMap<>();
        m.put("IV-1.1",  new HashSet<>(Arrays.asList(
                "executeQuery", "executeUpdate", "execute", "executeBatch",
                "createNativeQuery", "createQuery")));
        m.put("IV-1.3",  new HashSet<>(Arrays.asList(
                "new File", "new FileInputStream", "new FileOutputStream",
                "new FileReader", "Paths.get", "new URL",
                "openConnection", "new ServerSocket", "new Socket")));
        m.put("IV-1.4",  new HashSet<>(Arrays.asList(
                "print", "println", "write", "getWriter", "sendRedirect")));
        m.put("IV-1.5",  new HashSet<>(Arrays.asList(
                "exec", "ProcessBuilder", "command")));
        m.put("IV-1.9",  new HashSet<>(Arrays.asList(
                "evaluate", "executeXPath", "compile")));
        m.put("IV-1.10", new HashSet<>(Arrays.asList(
                "search", "InitialDirContext")));
        m.put("IV-1.12", new HashSet<>(Arrays.asList(
                "new URL", "openConnection", "getForObject", "exchange")));
        m.put("IV-1.13", new HashSet<>(Arrays.asList(
                "setHeader", "addHeader")));
        m.put("IV-1.17", new HashSet<>(Arrays.asList(
                "format", "printf", "MessageFormat.format")));
        m.put("IV-5.5",  new HashSet<>(Arrays.asList(
                "readObject", "readUnshared")));
        RULE_SINKS = Collections.unmodifiableMap(m);
    }

    // ── State per method analysis ─────────────────────────────────────────

    private final Map<String, TaintInfo> taintSet = new LinkedHashMap<>();
    private final List<Finding> findings = new ArrayList<>();
    private String currentFile;
    private SecurityRule currentRule;

    // ────────────────────────────────────────────────────────────────────
    // Public API
    // ────────────────────────────────────────────────────────────────────

    public List<Finding> analyze(CompilationUnit cu, String filePath,
                                 List<SecurityRule> rules) {
        this.currentFile = filePath;
        findings.clear();

        for (SecurityRule rule : rules) {
            if (!rule.isTaintAnalysis()) continue;
            this.currentRule = rule;

            cu.findAll(MethodDeclaration.class).forEach(method -> {
                taintSet.clear();
                method.accept(new TaintVisitor(), null);
            });
        }
        log.debug("[TaintAnalysis] {} — {}건 탐지", filePath, findings.size());
        return Collections.unmodifiableList(new ArrayList<>(findings));
    }

    // ────────────────────────────────────────────────────────────────────
    // AST Visitor
    // ────────────────────────────────────────────────────────────────────

    private class TaintVisitor extends VoidVisitorAdapter<Void> {

        @Override
        public void visit(VariableDeclarator n, Void arg) {
            super.visit(n, arg);
            if (!n.getInitializer().isPresent()) return;

            Expression init = n.getInitializer().get();
            String varName  = n.getNameAsString();
            int    line     = n.getBegin().map(p -> p.line).orElse(-1);

            if (isSourceCall(init)) {
                taintSet.put(varName, new TaintInfo(init.toString(), line, new ArrayList<>()));
            } else if (isTainted(init)) {
                List<String> propagators = collectTaintedVars(init);
                TaintInfo origin = propagators.isEmpty() ? null : taintSet.get(propagators.get(0));
                taintSet.put(varName, new TaintInfo(
                        origin != null ? origin.sourceExpr : init.toString(),
                        origin != null ? origin.sourceLine : line,
                        propagators));
            } else if (isSanitizerCall(init) && taintSet.containsKey(varName)) {
                taintSet.remove(varName);
            }
        }

        @Override
        public void visit(AssignExpr n, Void arg) {
            super.visit(n, arg);

            if (!(n.getTarget() instanceof NameExpr)) return;
            NameExpr target = (NameExpr) n.getTarget();
            String varName  = target.getNameAsString();
            int    line     = n.getBegin().map(p -> p.line).orElse(-1);
            Expression val  = n.getValue();

            if (isSourceCall(val)) {
                taintSet.put(varName, new TaintInfo(val.toString(), line, new ArrayList<>()));
            } else if (isTainted(val)) {
                List<String> propagators = collectTaintedVars(val);
                TaintInfo origin = propagators.isEmpty() ? null : taintSet.get(propagators.get(0));
                taintSet.put(varName, new TaintInfo(
                        origin != null ? origin.sourceExpr : val.toString(),
                        origin != null ? origin.sourceLine : line,
                        propagators));
            } else if (isSanitizerCall(val)) {
                taintSet.remove(varName);
            }
        }

        @Override
        public void visit(MethodCallExpr n, Void arg) {
            super.visit(n, arg);

            String methodName = n.getNameAsString();
            int    line       = n.getBegin().map(p -> p.line).orElse(-1);

            // ① Sink 탐지
            Set<String> sinks = RULE_SINKS.getOrDefault(currentRule.getRuleId(), Collections.emptySet());
            if (sinks.contains(methodName)) {
                for (Expression argExpr : n.getArguments()) {
                    if (isTainted(argExpr)) {
                        String taintedVar = firstTaintedVar(argExpr);
                        TaintInfo info = taintSet.get(taintedVar);
                        reportFinding(info, taintedVar, n.toString(), line);
                    }
                }
            }

            // ② Sanitizer — 관련 변수 오염 제거
            if (SANITIZER_METHODS.contains(methodName)) {
                for (Expression argExpr : n.getArguments()) {
                    if (argExpr instanceof NameExpr) {
                        taintSet.remove(((NameExpr) argExpr).getNameAsString());
                    }
                }
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // Helper Methods
    // ────────────────────────────────────────────────────────────────────

    private boolean isSourceCall(Expression expr) {
        if (expr instanceof MethodCallExpr) {
            return SOURCE_METHODS.contains(((MethodCallExpr) expr).getNameAsString());
        }
        return false;
    }

    private boolean isSanitizerCall(Expression expr) {
        if (expr instanceof MethodCallExpr) {
            return SANITIZER_METHODS.contains(((MethodCallExpr) expr).getNameAsString());
        }
        return false;
    }

    private boolean isTainted(Expression expr) {
        if (expr instanceof NameExpr) {
            return taintSet.containsKey(((NameExpr) expr).getNameAsString());
        }
        if (expr instanceof BinaryExpr) {
            BinaryExpr be = (BinaryExpr) expr;
            return isTainted(be.getLeft()) || isTainted(be.getRight());
        }
        if (expr instanceof MethodCallExpr) {
            MethodCallExpr call = (MethodCallExpr) expr;
            boolean scopeTainted = call.getScope()
                    .filter(s -> s instanceof NameExpr
                              && taintSet.containsKey(((NameExpr) s).getNameAsString()))
                    .isPresent();
            boolean argTainted = call.getArguments().stream().anyMatch(this::isTainted);
            return scopeTainted || argTainted;
        }
        if (expr instanceof EnclosedExpr) {
            return isTainted(((EnclosedExpr) expr).getInner());
        }
        if (expr instanceof CastExpr) {
            return isTainted(((CastExpr) expr).getExpression());
        }
        return false;
    }

    private List<String> collectTaintedVars(Expression expr) {
        List<String> result = new ArrayList<>();
        collectTaintedVarsRecursive(expr, result);
        return result;
    }

    private void collectTaintedVarsRecursive(Expression expr, List<String> out) {
        if (expr instanceof NameExpr) {
            String name = ((NameExpr) expr).getNameAsString();
            if (taintSet.containsKey(name)) out.add(name);
        } else if (expr instanceof BinaryExpr) {
            BinaryExpr be = (BinaryExpr) expr;
            collectTaintedVarsRecursive(be.getLeft(), out);
            collectTaintedVarsRecursive(be.getRight(), out);
        } else if (expr instanceof MethodCallExpr) {
            MethodCallExpr call = (MethodCallExpr) expr;
            call.getScope().ifPresent(s -> collectTaintedVarsRecursive(s, out));
            call.getArguments().forEach(a -> collectTaintedVarsRecursive(a, out));
        }
    }

    private String firstTaintedVar(Expression expr) {
        List<String> vars = collectTaintedVars(expr);
        return vars.isEmpty() ? "<unknown>" : vars.get(0);
    }

    private void reportFinding(TaintInfo info, String taintedVar,
                               String sinkExpr, int sinkLine) {
        String sourceExpr = info != null ? info.sourceExpr : "unknown";
        int    sourceLine = info != null ? info.sourceLine : -1;
        List<String> props = info != null ? info.propagators : Collections.emptyList();

        Finding.TaintFlow flow = new Finding.TaintFlow(
                sourceExpr, sourceLine, props, sinkExpr, sinkLine);

        findings.add(Finding.builder()
                .ruleId(currentRule.getRuleId())
                .ruleName(currentRule.getName())
                .severity(Finding.Severity.valueOf(currentRule.getSeverity()))
                .filePath(currentFile)
                .lineNumber(sinkLine)
                .vulnerableCode(sinkExpr)
                .description(String.format(
                        "외부 입력값 '%s'(%s, L%d)이 검증 없이 %s(L%d)에 사용됩니다.",
                        taintedVar, sourceExpr, sourceLine, sinkExpr, sinkLine))
                .taintFlows(Collections.singletonList(flow))
                .guideRef(currentRule.getGuideRef())
                .cweIds(currentRule.getCwe())
                .build());
    }

    // ── Inner Data Class ─────────────────────────────────────────────────

    private static class TaintInfo {
        final String       sourceExpr;
        final int          sourceLine;
        final List<String> propagators;

        TaintInfo(String sourceExpr, int sourceLine, List<String> propagators) {
            this.sourceExpr  = sourceExpr;
            this.sourceLine  = sourceLine;
            this.propagators = propagators;
        }
    }
}
