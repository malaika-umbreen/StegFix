import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import Login from './pages/Login';
import Signup from './pages/Signup';
import Dashboard from './pages/Dashboard';
import FlowDetails from './pages/FlowDetails';
import TechniqueAnalysis from './pages/TechniqueAnalysis';
import ProtocolAnalysis from './pages/ProtocolAnalysis';
import Logs from './pages/Logs';
import Settings from './pages/Settings';


function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/flow-details" element={<FlowDetails />} />
          <Route path="/technique-analysis" element={<TechniqueAnalysis />} />
          <Route path="/protocol-analysis" element={<ProtocolAnalysis />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/" element={<Navigate to="/login" replace />} />
        </Routes>
        
      </BrowserRouter>  
    </AuthProvider>
  );
}

export default App;
