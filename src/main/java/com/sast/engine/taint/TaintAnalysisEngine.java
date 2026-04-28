package com.sast.engine.taint;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.sast.engine.rules.SecurityRule;
import com.sast.model.Finding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Taint Analysis Engine — Source → Propagator → Sink 흐름 탐지
 *
 * 알고리즘: 인트라-프로시저럴 Dataflow (메서드 단위)
 * 지원 규칙: taintAnalysis: true 인 모든 IV-x.x 규칙
 */
public class TaintAnalysisEngine {

    private static final Logger log = LoggerFactory.getLogger(TaintAnalysisEngine.class);

    // ── Source Signatures ────────────────────────────────────────────────

    private static final Set<String> SOURCE_METHODS = new HashSet<>(Arrays.asList(
            "getParameter", "getAttribute", "getQueryString",
            "getHeader", "getCookies", "getInputStream", "getReader",
            "getenv", "getProperty",
            "readLine", "readAllBytes",
            "getSession"   // DS-4.1: 세션 객체 전달 탐지용 (서비스 레이어 전달 시 DS-4.1 위반)
            // readObject / readUnshared 는 IV-5.5 의 Sink — Source 에 두지 않음
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

    // ── Method-Call Sink Signatures (Rule별 매핑) ─────────────────────────

    private static final Map<String, Set<String>> RULE_SINKS;

    // ── Constructor-Call Sink Signatures (ObjectCreationExpr 기반) ────────
    // 생성자 자체가 Sink인 경우 — new File(tainted), new FileInputStream(tainted)

    private static final Map<String, Set<String>> RULE_CTOR_SINKS;

    static {
        Map<String, Set<String>> m = new HashMap<>();
        m.put("IV-1.1",  new HashSet<>(Arrays.asList(
                "executeQuery", "executeUpdate", "execute", "executeBatch",
                "createNativeQuery", "createQuery")));
        // IV-1.2 코드삽입: ScriptEngine.eval(), Runtime.exec()
        m.put("IV-1.2",  new HashSet<>(Arrays.asList(
                "eval", "executeScript")));
        // IV-1.4 XSS
        m.put("IV-1.4",  new HashSet<>(Arrays.asList(
                "print", "println", "write", "getWriter")));
        // IV-1.5 OS 명령어 삽입
        m.put("IV-1.5",  new HashSet<>(Arrays.asList(
                "exec", "command")));
        // IV-1.7 URL 자동접속: HttpServletResponse.sendRedirect()
        m.put("IV-1.7",  new HashSet<>(Arrays.asList(
                "sendRedirect")));
        m.put("IV-1.9",  new HashSet<>(Arrays.asList(
                "evaluate", "executeXPath", "compile")));
        m.put("IV-1.10", new HashSet<>(Arrays.asList(
                "search", "InitialDirContext")));
        // IV-1.12 SSRF: url.openConnection() — scope(url)이 오염된 경우 탐지
        m.put("IV-1.12", new HashSet<>(Arrays.asList(
                "openConnection", "getForObject", "exchange")));
        m.put("IV-1.13", new HashSet<>(Arrays.asList(
                "setHeader", "addHeader")));
        // IV-1.15 보안기능 결정: session.setAttribute(), Cookie.setSecure()
        m.put("IV-1.15", new HashSet<>(Arrays.asList(
                "setAttribute", "setSecure", "setMaxInactiveInterval")));
        m.put("IV-1.17", new HashSet<>(Arrays.asList(
                "format", "printf")));
        // IV-5.5 역직렬화: ois.readObject() — scope(ois)이 오염된 경우 탐지
        m.put("IV-5.5",  new HashSet<>(Arrays.asList(
                "readObject", "readUnshared")));
        RULE_SINKS = Collections.unmodifiableMap(m);

        Map<String, Set<String>> c = new HashMap<>();
        // IV-1.3 경로조작: new File(tainted), new FileInputStream(tainted) 등
        c.put("IV-1.3",  new HashSet<>(Arrays.asList(
                "File", "FileInputStream", "FileOutputStream",
                "FileReader", "RandomAccessFile")));
        RULE_CTOR_SINKS = Collections.unmodifiableMap(c);
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
            // DS-4.1: 세션 객체가 서비스 레이어 메서드 파라미터로 선언된 패턴을 구조적으로 탐지
            if ("DS-4.1".equals(rule.getRuleId())) {
                findings.addAll(detectSessionParamInService(cu, filePath, rule));
                continue;
            }

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

    /**
     * DS-4.1 세션 통제 — 구조적 탐지
     *
     * 컨트롤러가 아닌 서비스/유틸 클래스의 메서드가 HttpSession 객체를 파라미터로
     * 직접 받는 패턴을 탐지한다. 세션 객체 전체를 전달하면:
     *   1) 세션 데이터 변조 가능성
     *   2) 세션 고정(Session Fixation) 공격 취약
     *   3) 세션 만료 시 NPE 위험
     * 대신 필요한 속성값(ID, 권한 등)만 추출하여 인수로 전달해야 한다.
     */
    private List<Finding> detectSessionParamInService(CompilationUnit cu, String filePath,
                                                       SecurityRule rule) {
        List<Finding> result = new ArrayList<>();
        String guideRef = rule.getGuideRef();

        cu.findAll(ClassOrInterfaceDeclaration.class).forEach(classDecl -> {
            // 컨트롤러 계층은 제외 (Spring MVC는 컨트롤러에서 HttpSession 주입을 허용)
            boolean isController = classDecl.getAnnotations().stream()
                    .anyMatch(a -> {
                        String n = a.getNameAsString();
                        return n.contains("Controller") || n.contains("WebServlet");
                    });
            // 클래스 이름에 Controller가 포함되어도 컨트롤러로 간주 (어노테이션 미탐지 보완)
            if (isController || classDecl.getNameAsString().endsWith("Controller")) return;

            classDecl.getMethods().forEach(method -> {
                method.getParameters().forEach(param -> {
                    String typeName = param.getTypeAsString();
                    // HttpSession 타입 파라미터 탐지
                    if (!typeName.contains("HttpSession")) return;

                    int paramLine = param.getBegin().map(p -> p.line).orElse(-1);
                    String methodSig = classDecl.getNameAsString() + "." +
                            method.getNameAsString() + "(" + typeName + " " +
                            param.getNameAsString() + ", ...)";

                    result.add(Finding.builder()
                            .ruleId(rule.getRuleId())
                            .ruleName(rule.getName())
                            .severity(Finding.Severity.valueOf(rule.getSeverity()))
                            .filePath(filePath)
                            .lineNumber(paramLine)
                            .vulnerableCode(method.getDeclarationAsString(false, false, true))
                            .description(String.format(
                                    "서비스/유틸 클래스 '%s'의 메서드 '%s'가 HttpSession 객체를 직접 파라미터로 " +
                                    "받습니다. 세션 객체 전달 시 불필요한 데이터 접근·변조 위험이 있으므로, " +
                                    "session.getAttribute(\"admin\") 등 필요한 속성값만 추출하여 전달하세요.",
                                    classDecl.getNameAsString(), method.getNameAsString()))
                            .taintFlows(Collections.emptyList())
                            .guideRef(guideRef)
                            .cweIds(rule.getCwe())
                            .build());
                });
            });
        });

        return result;
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
            } else if (init instanceof ObjectCreationExpr) {
                // new Foo(taintedArg) → 오염 전파 (생성된 객체 변수도 오염)
                propagateTaintFromCtor((ObjectCreationExpr) init, varName, line);
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
            } else if (val instanceof ObjectCreationExpr) {
                propagateTaintFromCtor((ObjectCreationExpr) val, varName, line);
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

        /**
         * ObjectCreationExpr Sink 탐지 — IV-1.3 경로조작 등
         * new File(taintedPath), new FileInputStream(taintedPath) 패턴
         */
        @Override
        public void visit(ObjectCreationExpr n, Void arg) {
            super.visit(n, arg);

            String typeName = n.getTypeAsString();
            Set<String> ctorSinks = RULE_CTOR_SINKS.getOrDefault(
                    currentRule.getRuleId(), Collections.emptySet());
            int line = n.getBegin().map(p -> p.line).orElse(-1);

            if (ctorSinks.contains(typeName)) {
                for (Expression argExpr : n.getArguments()) {
                    if (isTainted(argExpr)) {
                        String taintedVar = firstTaintedVar(argExpr);
                        TaintInfo info = taintSet.get(taintedVar);
                        reportFinding(info, taintedVar, n.toString(), line);
                    }
                }
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
                boolean argFired = false;
                for (Expression argExpr : n.getArguments()) {
                    if (isTainted(argExpr)) {
                        String taintedVar = firstTaintedVar(argExpr);
                        TaintInfo info = taintSet.get(taintedVar);
                        reportFinding(info, taintedVar, n.toString(), line);
                        argFired = true;
                    }
                }
                // 인자에 오염 없으면 scope(수신 객체) 오염 여부 확인
                // — ois.readObject(), url.openConnection() 패턴
                if (!argFired) {
                    n.getScope().ifPresent(scope -> {
                        if (isTainted(scope)) {
                            String taintedVar = firstTaintedVar(scope);
                            TaintInfo info = taintSet.get(taintedVar);
                            reportFinding(info, taintedVar, n.toString(), line);
                        }
                    });
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

    /**
     * ObjectCreationExpr 의 인자에 오염값이 있으면 대상 변수(varName)를 오염 처리.
     * Sink 탐지와 독립적으로 동작하는 전파 로직.
     */
    private void propagateTaintFromCtor(ObjectCreationExpr oce, String varName, int line) {
        Optional<Expression> firstTainted = oce.getArguments().stream()
                .filter(this::isTainted)
                .findFirst();
        if (firstTainted.isEmpty()) return;

        List<String> propagators = collectTaintedVars(firstTainted.get());
        TaintInfo origin = propagators.isEmpty() ? null : taintSet.get(propagators.get(0));
        taintSet.put(varName, new TaintInfo(
                origin != null ? origin.sourceExpr : oce.toString(),
                origin != null ? origin.sourceLine : line,
                propagators));
    }

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
        if (expr instanceof ObjectCreationExpr) {
            return ((ObjectCreationExpr) expr).getArguments().stream().anyMatch(this::isTainted);
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
        } else if (expr instanceof ObjectCreationExpr) {
            ((ObjectCreationExpr) expr).getArguments()
                    .forEach(a -> collectTaintedVarsRecursive(a, out));
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
