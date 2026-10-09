import { BrowserRouter, Link, Route, Routes } from 'react-router-dom'
import { MonitorProvider } from './context/MonitorContext'
import { Layout } from './components/Layout'
import { lazy, Suspense } from 'react'
const Overview = lazy(() => import('./pages/Overview'))
import Monitor from './pages/Monitor'
import Devices from './pages/Devices'
import Incidents from './pages/Incidents'
import Threats from './pages/Threats'
import Defense from './pages/Defense'
import Settings from './pages/Settings'
import { AlertProvider } from './context/AlertContext'
import './App.css'
export default function App() { return <BrowserRouter><MonitorProvider><AlertProvider><Routes><Route element={<Layout />}><Route index element={<Suspense fallback={<p className="feedback" role="status">Loading overview…</p>}><Overview /></Suspense>} /><Route path="monitor" element={<Monitor />} /><Route path="devices" element={<Devices />} /><Route path="threats" element={<Threats />} /><Route path="incidents" element={<Incidents />} /><Route path="defense" element={<Defense />} /><Route path="settings" element={<Settings />} /><Route path="*" element={<div className="empty-state"><h1>Page not found</h1><p>This page is not part of your workspace.</p><Link className="button" to="/">Back to overview</Link></div>} /></Route></Routes></AlertProvider></MonitorProvider></BrowserRouter> }
