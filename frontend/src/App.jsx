import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import ScannerPage from './pages/ScannerPage';
import ResultPage from './pages/ResultPage';
import HistoryPage from './pages/HistoryPage';
import AboutPage from './pages/AboutPage';
import AboutAppPage from './pages/AboutAppPage';

export default function App() {
  return (
    <BrowserRouter>
      <Navbar />
      <Routes>
        <Route path="/" element={<ScannerPage />} />
        <Route path="/scan" element={<ScannerPage />} />
        <Route path="/history" element={<HistoryPage />} />
        <Route path="/about-app" element={<AboutAppPage />} />
        <Route path="/about" element={<AboutPage />} />
        <Route path="/results/:scanId" element={<ResultPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      <Footer />
    </BrowserRouter>
  );
}
