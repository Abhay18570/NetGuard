import { useEffect, useRef, useState } from 'react'
import { NavLink, Outlet, Link } from 'react-router-dom'
import { Shield, LayoutDashboard, Radio, Network, ScanLine, History, ShieldCheck, Settings, Menu, X, ChartNoAxesCombined } from 'lucide-react'
import { useMonitor } from '../context/useMonitor'
const navigation = [ ['/', 'Overview', LayoutDashboard], ['/monitor', 'Live ARP Monitor', Radio], ['/analytics', 'Network Analytics', ChartNoAxesCombined], ['/devices', 'Network Devices', Network], ['/threats', 'Threat Detection', ScanLine], ['/incidents', 'Incident History', History], ['/defense', 'Defense Center', ShieldCheck], ['/settings', 'Settings', Settings] ] as const
export function Layout() {
  const [open, setOpen] = useState(false)
  const menu = useRef<HTMLButtonElement>(null)
  useEffect(() => {
    if (!open) return
    const escape = (event: KeyboardEvent) => { if (event.key === 'Escape') { setOpen(false); menu.current?.focus() } }
    document.addEventListener('keydown', escape)
    return () => document.removeEventListener('keydown', escape)
  }, [open])
  const { connection, error } = useMonitor()
  return <div className="app-shell"><a className="skip-link" href="#main">Skip to content</a>{open && <button className="sidebar-backdrop" aria-label="Close navigation" onClick={() => setOpen(false)} />}
    <aside id="workspace-navigation" className={`sidebar ${open ? 'open' : ''}`}><Link to="/" className="brand" onClick={() => setOpen(false)}><span className="brand-icon"><Shield size={24} /></span><span>NetGuard</span></Link><button className="mobile-close icon-button" aria-label="Close navigation" onClick={() => setOpen(false)}><X /></button><nav aria-label="Main navigation">{navigation.map(([path, label, Icon]) => <NavLink key={path} to={path} end={path === '/'} onClick={() => setOpen(false)}><Icon size={18} /><span>{label}</span></NavLink>)}</nav></aside>
    <div className="main-shell"><header className="topbar"><button className="icon-button mobile-menu" ref={menu} aria-controls="workspace-navigation" aria-label="Open navigation" aria-expanded={open} onClick={() => setOpen(true)}><Menu size={20} /></button><span className={`connection-label ${connection === 'connected' ? 'connected' : 'disconnected'}`}><span className="tiny-dot" />{connection === 'connected' ? 'Connected' : connection === 'loading' ? 'Connecting…' : 'Disconnected'}</span></header><main id="main">{error && <div role="alert" className="error-banner">{error}</div>}<Outlet /></main></div>
  </div>
}
