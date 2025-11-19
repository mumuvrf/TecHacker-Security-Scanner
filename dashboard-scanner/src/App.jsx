import React, { useState, useEffect, useMemo } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { FileText, Globe, AlertTriangle, Users, Database, Server, Terminal } from 'lucide-react';

// --- Constantes e Configurações ---
const RISK_ORDER = ["Crítico", "Alto", "Médio", "Baixo", "Informacional"];
const RISK_COLORS = {
    "Crítico": "red", "Alto": "orange", "Médio": "yellowgreen", "Baixo": "skyblue", "Informacional": "gray"
};
const CHART_COLORS = { "Crítico": '#ef4444', "Alto": '#f97316', "Médio": '#facc15', "Baixo": '#3b82f6', "Informacional": '#9ca3af' };

// Endereço da sua API FastAPI
const API_SCAN_URL = 'http://localhost:8000/run'; 

// --- DADOS MOCK INICIAIS ---
// Mock de relatório, garantindo que contenha a chave markdownContent (mesmo que vazia no mock)
const initialMockReport = {
    id: 'mock-001',
    url: 'https://seusite-mock.com',
    timestamp: new Date().toISOString(), 
    displayDate: new Date().toLocaleDateString('pt-BR'),
    totalFindings: 3,
    riskCounts: {
        "Crítico": 1,
        "Alto": 1,
        "Médio": 1,
        "Baixo": 0,
        "Informacional": 0
    },
    vulnerabilities: [
        { type: "Injeção SQL (Mock)", description: "Vulnerabilidade crítica simulada.", risk: "Crítico", mitigation: "Usar Prepared Statements." },
        { type: "XSS Refletido (Mock)", description: "Vulnerabilidade de alto risco simulada.", risk: "Alto", mitigation: "Sanitizar entradas de usuário." },
        { type: "Headers Inseguros (Mock)", description: "Vulnerabilidade de risco médio simulada.", risk: "Médio", mitigation: "Adicionar HSTS e CSP." },
    ],
    // CHAVE ADICIONADA: O backend real deve preencher isso com a string Markdown
    markdownContent: "# Relatório de Teste\n\nEste é um conteúdo Markdown simulado. O conteúdo real será gerado pelo FastAPI." 
};

const App = () => {
    const [mockUserId] = useState('user-mock-123456');
    const [reports, setReports] = useState([initialMockReport]);
    const [activeReport, setActiveReport] = useState(initialMockReport);
    const [isLoading, setIsLoading] = useState(true);
    const [scanUrl, setScanUrl] = useState('');
    const [isScanning, setIsScanning] = useState(false);
    const [error, setError] = useState(null);

    // Mock de Inicialização
    useEffect(() => {
        setTimeout(() => {
            setIsLoading(false);
        }, 500);
    }, []);

    // 🌟 FUNÇÃO DE DOWNLOAD MARKDOWN
    const handleDownloadMarkdown = () => {
        if (!activeReport || !activeReport.markdownContent) {
            alert("Nenhum relatório ou conteúdo Markdown disponível para download.");
            return;
        }

        // 1. Cria um Blob (objeto binário) a partir da string Markdown
        const blob = new Blob([activeReport.markdownContent], { type: 'text/markdown;charset=utf-8' });

        // 2. Cria um URL e um link temporário para iniciar o download
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        
        link.download = `scan_report_${activeReport.id}.md`; 
        link.href = url;
        
        // 3. Simula um clique no link e inicia o download
        document.body.appendChild(link);
        link.click();
        
        // 4. Limpeza de objetos temporários
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    };

    // Disparo do Scan e Persistência em Memória
    const handleStartScan = async () => {
        if (!scanUrl || isScanning || !mockUserId) return; 

        setIsScanning(true);
        setError(null);
        
        try {
            const apiResponse = await fetch(API_SCAN_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: scanUrl })
            });

            if (!apiResponse.ok) {
                const errorBody = await apiResponse.text();
                throw new Error(`API Error (${apiResponse.status}): ${errorBody.substring(0, 100)}`);
            }

            const rawData = await apiResponse.json();
            const reportId = rawData.id || `scan_${Date.now()}`; // Usa ID do backend, ou gera um
            
            // NORMALIZAÇÃO DE DADOS (INCLUINDO markdownContent)
            const formattedReport = {
                id: reportId,
                url: rawData.metadata.target_url, 
                timestamp: new Date().toISOString(), 
                displayDate: new Date().toLocaleDateString('pt-BR'),
                totalFindings: rawData.metadata.total_findings,
                riskCounts: rawData.summary.risk_counts,
                vulnerabilities: rawData.vulnerabilities,
                // CHAVE CRUCIAL: PEGA O CONTEÚDO MARKDOWN GERADO PELO BACKEND
                markdownContent: rawData.markdownContent, 
                hasStructuredData: true 
            };

            setReports(prevReports => [formattedReport, ...prevReports]);
            setScanUrl('');
            setActiveReport(formattedReport);

        } catch (e) {
            console.error("Scan Error:", e);
            setError(`Falha no scan: ${e.message}`);
        } finally {
            setIsScanning(false);
        }
    };
    
    // Cálculos de UI (inalterados)
    const riskScore = useMemo(() => {
        if (!activeReport || !activeReport.riskCounts) return 0;
        const counts = activeReport.riskCounts;
        const score = ((counts["Crítico"] || 0) * 10) + ((counts["Alto"] || 0) * 5) + ((counts["Médio"] || 0) * 2);
        return Math.min(100, score > 0 ? Math.min(100, 20 + score) : 0); 
    }, [activeReport]);

    const chartData = useMemo(() => {
        if (!activeReport || !activeReport.riskCounts) return [];
        return RISK_ORDER.map(risk => ({
            name: risk,
            count: activeReport.riskCounts[risk] || 0,
            fill: CHART_COLORS[risk]
        })); 
    }, [activeReport]);

    // --- Componentes Visuais (CSS Puro) ---

    const StatCard = ({ title, value, color, icon: Icon }) => (
        <div style={{ padding: '15px', borderRadius: '8px', boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', backgroundColor: color, color: color === 'yellowgreen' ? '#333' : 'white' }}>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
                <span style={{ fontSize: '14px', fontWeight: '500', opacity: '0.9' }}>{title}</span>
                <span style={{ fontSize: '24px', fontWeight: 'bold', marginTop: '4px' }}>{value}</span>
            </div>
            <Icon size={28} style={{ opacity: '0.7' }}/>
        </div>
    );

    const VulnerabilityList = ({ vulnerabilities }) => (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {vulnerabilities.map((vuln, index) => (
                <div key={index} style={{ padding: '15px', border: '1px solid #ccc', borderRadius: '8px', boxShadow: '0 2px 4px rgba(0, 0, 0, 0.05)', backgroundColor: 'white' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                        <span style={{ padding: '4px 8px', fontSize: '10px', fontWeight: 'bold', borderRadius: '999px', backgroundColor: RISK_COLORS[vuln.risk], color: 'white' }}>
                            {vuln.risk.toUpperCase()}
                        </span>
                        <span style={{ fontSize: '12px', color: '#555' }}>{vuln.type}</span>
                    </div>
                    
                    <p style={{ color: '#333', fontSize: '14px', marginBottom: '12px' }}>{vuln.description}</p>
                    
                    {vuln.technical_details && (
                        <div style={{ backgroundColor: '#222', color: '#0f0', borderRadius: '4px', padding: '10px', fontSize: '11px', fontFamily: 'monospace', overflowX: 'auto', marginBottom: '12px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid #444', paddingBottom: '5px', marginBottom: '5px', color: '#aaa' }}>
                                <Terminal size={12} /> Detalhes Técnicos
                            </div>
                            <pre style={{ margin: 0 }}>{JSON.stringify(vuln.technical_details, null, 2)}</pre>
                        </div>
                    )}

                    <div style={{ borderTop: '1px solid #eee', paddingTop: '10px', marginTop: '10px' }}>
                        <span style={{ fontSize: '12px', fontWeight: 'bold', color: 'darkblue', textTransform: 'uppercase' }}>Mitigação Sugerida:</span>
                        <p style={{ fontSize: '13px', color: '#555', marginTop: '4px' }}>{vuln.mitigation}</p>
                    </div>
                </div>
            ))}
        </div>
    );

    if (isLoading) return <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', backgroundColor: '#f4f4f4', fontSize: '20px', fontWeight: 'bold' }}>Carregando Dashboard...</div>;

    return (
        <div style={{ display: 'flex', minHeight: '100vh', width: '100%', fontFamily: 'sans-serif', backgroundColor: '#f4f4f4', color: '#333' }}>
            
            {/* Sidebar (280px) */}
            <div style={{ width: '280px', backgroundColor: '#2c3e50', color: 'white', display: 'flex', flexDirection: 'column', boxShadow: '2px 0 5px rgba(0,0,0,0.3)' }}>
                <div style={{ padding: '20px', borderBottom: '1px solid #3c5067' }}>
                    <h1 style={{ fontSize: '24px', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <Server style={{ color: '#3498db' }}/> Scanner Pro
                    </h1>
                    <p style={{ fontSize: '10px', color: '#bdc3c7', marginTop: '5px' }}>Usuário Mock: {mockUserId.substring(0, 10)}...</p>
                </div>
                
                <div style={{ padding: '20px', borderBottom: '1px solid #3c5067' }}>
                    <label style={{ fontSize: '12px', fontWeight: 'bold', color: '#bdc3c7', textTransform: 'uppercase', marginBottom: '8px', display: 'block' }}>Novo Alvo</label>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        <input 
                            type="url" 
                            placeholder="https://exemplo.com" 
                            value={scanUrl}
                            onChange={(e) => setScanUrl(e.target.value)}
                            style={{ padding: '8px', borderRadius: '4px', border: '1px solid #555', backgroundColor: '#34495e', color: 'white' }}
                        />
                        <button
                            onClick={handleStartScan}
                            disabled={isScanning || scanUrl.length < 8}
                            style={{ padding: '10px', borderRadius: '4px', fontWeight: 'bold', border: 'none', cursor: isScanning ? 'wait' : 'pointer', transition: 'background-color 0.3s', backgroundColor: isScanning ? '#2980b9' : '#3498db', color: 'white' }}
                        >
                            {isScanning ? 'Varrendo Alvo...' : 'Iniciar Scan'}
                        </button>
                    </div>
                    {error && <div style={{ marginTop: '10px', fontSize: '12px', color: '#e74c3c', backgroundColor: 'rgba(231, 76, 60, 0.1)', padding: '5px', borderRadius: '4px', border: '1px solid #e74c3c' }}>Erro: {error}</div>}
                </div>

                <div style={{ flex: 1, overflowY: 'auto' }}>
                    <h3 style={{ padding: '10px 20px', fontSize: '14px', fontWeight: 'bold', color: '#bdc3c7', textTransform: 'uppercase' }}>Histórico</h3>
                    {reports.map((report) => (
                        <div
                            key={report.id}
                            onClick={() => setActiveReport(report)}
                            style={{ padding: '12px 20px', borderLeft: `4px solid ${activeReport && activeReport.id === report.id ? '#3498db' : 'transparent'}`, cursor: 'pointer', transition: 'background-color 0.1s', backgroundColor: activeReport && activeReport.id === report.id ? '#34495e' : 'transparent', ':hover': { backgroundColor: '#34495e' } }}
                        >
                            <p style={{ fontSize: '14px', fontWeight: '500', color: 'white', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{report.url}</p>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px' }}>
                                <span style={{ fontSize: '10px', color: '#bdc3c7' }}>{new Date(report.timestamp).toLocaleDateString()}</span>
                                <span style={{ fontSize: '10px', padding: '2px 5px', borderRadius: '3px', backgroundColor: report.totalFindings > 0 ? '#e74c3c' : '#27ae60', color: 'white' }}>
                                    {report.totalFindings} vulns
                                </span>
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Main Content */}
            <div style={{ flex: 1, padding: '30px', overflowY: 'auto' }}>
                <header style={{ marginBottom: '25px' }}>
                    <h2 style={{ fontSize: '30px', fontWeight: 'bold', color: '#333' }}>Visão Geral de Segurança</h2>
                </header>
                
                {activeReport ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '25px' }}>
                        
                        {/* KPI Cards */}
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '15px' }}>
                            <StatCard 
                                title="Nível de Risco" 
                                value={riskScore > 50 ? "Alto" : riskScore > 20 ? "Médio" : "Baixo"} 
                                color={riskScore > 50 ? '#e74c3c' : riskScore > 20 ? 'orange' : '#2ecc71'}
                                icon={AlertTriangle}
                            />
                            <StatCard 
                                title="Total de Achados" 
                                value={activeReport.totalFindings} 
                                color="#3498db"
                                icon={Database}
                            />
                            <StatCard 
                                title="Críticos / Altos" 
                                value={(activeReport.riskCounts?.["Crítico"] || 0) + (activeReport.riskCounts?.["Alto"] || 0)} 
                                color="#e74c3c"
                                icon={AlertTriangle}
                            />
                            <StatCard 
                                title="Alvo" 
                                value={activeReport.url.replace(/(^\w+:|^)\/\//, '').substring(0, 18) + (activeReport.url.length > 18 ? '...' : '')} 
                                color="#95a5a6"
                                icon={Globe}
                            />
                        </div>

                        {/* Gráfico e Resumo */}
                        <div style={{ display: 'grid', gridTemplateColumns: '70% 30%', gap: '20px' }}>
                            {/* Chart Section */}
                            <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '8px', boxShadow: '0 2px 4px rgba(0,0,0,0.1)', border: '1px solid #ddd' }}>
                                <h3 style={{ fontSize: '18px', fontWeight: 'bold', color: '#333', marginBottom: '15px' }}>Distribuição de Severidade</h3>
                                <div style={{ height: '250px' }}>
                                    <ResponsiveContainer width="100%" height="100%">
                                        <BarChart data={chartData}>
                                            <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#eee" />
                                            <XAxis dataKey="name" axisLine={false} tickLine={false} style={{ fontSize: '12px', fill: '#555' }} />
                                            <YAxis axisLine={false} tickLine={false} style={{ fontSize: '12px', fill: '#555' }} allowDecimals={false}/>
                                            <Tooltip />
                                            <Bar dataKey="count" />
                                        </BarChart>
                                    </ResponsiveContainer>
                                </div>
                            </div>

                            {/* Summary Details */}
                            <div style={{ backgroundColor: 'white', padding: '20px', borderRadius: '8px', boxShadow: '0 2px 4px rgba(0,0,0,0.1)', border: '1px solid #ddd', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                                <div>
                                    <h3 style={{ fontSize: '18px', fontWeight: 'bold', color: '#333', marginBottom: '15px' }}>Resumo do Scan</h3>
                                    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                                        <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #eee', paddingBottom: '5px' }}>
                                            <span style={{ color: '#777', fontSize: '14px' }}>Data:</span>
                                            <span style={{ fontWeight: '500', fontSize: '14px' }}>{activeReport.displayDate || 'N/A'}</span>
                                        </div>
                                        <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #eee', paddingBottom: '5px' }}>
                                            <span style={{ color: '#777', fontSize: '14px' }}>Status:</span>
                                            <span style={{ fontWeight: '500', fontSize: '14px', color: '#27ae60' }}>Concluído</span>
                                        </div>
                                        <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #eee', paddingBottom: '5px' }}>
                                            <span style={{ color: '#777', fontSize: '14px' }}>ID:</span>
                                            <span style={{ fontFamily: 'monospace', fontSize: '12px', backgroundColor: '#eee', padding: '2px 5px', borderRadius: '3px' }}>{activeReport.id}</span>
                                        </div>
                                    </div>
                                </div>
                                
                                {/* BOTÃO DE DOWNLOAD AQUI */}
                                <button
                                    onClick={handleDownloadMarkdown}
                                    disabled={!activeReport || !activeReport.markdownContent || isScanning}
                                    style={{ 
                                        marginTop: '15px',
                                        width: '100%', 
                                        padding: '10px', 
                                        borderRadius: '4px', 
                                        backgroundColor: '#3498db', 
                                        color: 'white', 
                                        border: 'none',
                                        cursor: (!activeReport || !activeReport.markdownContent || isScanning) ? 'not-allowed' : 'pointer',
                                        fontWeight: 'bold',
                                        opacity: (!activeReport || !activeReport.markdownContent || isScanning) ? 0.6 : 1
                                    }}
                                >
                                    Baixar Relatório (.md)
                                </button>
                            </div>
                        </div>

                        {/* Vulnerability List */}
                        <div>
                            <h3 style={{ fontSize: '20px', fontWeight: 'bold', color: '#333', marginBottom: '15px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                                <FileText style={{ color: '#3498db' }}/> Detalhes das Vulnerabilidades
                            </h3>
                            {activeReport.vulnerabilities && activeReport.vulnerabilities.length > 0 ? (
                                <VulnerabilityList vulnerabilities={activeReport.vulnerabilities} />
                            ) : (
                                <div style={{ backgroundColor: '#ecf0f1', border: '1px solid #bdc3c7', borderRadius: '8px', padding: '30px', textAlign: 'center', color: '#7f8c8d' }}>
                                    <p style={{ fontWeight: 'bold', fontSize: '18px' }}>Nenhuma vulnerabilidade encontrada!</p>
                                </div>
                            )}
                        </div>

                    </div>
                ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '400px', color: '#95a5a6', backgroundColor: 'white', borderRadius: '8px', border: '2px dashed #ccc' }}>
                        <Server size={48} style={{ marginBottom: '15px', opacity: '0.4'}}/>
                        <p>Selecione um relatório ou inicie um novo scan.</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default App;