export default function ThemeInit() {
  const code = `try{var s=localStorage.getItem('bacha-theme'),d=matchMedia('(prefers-color-scheme: dark)').matches;document.documentElement.setAttribute('data-bs-theme',s==='light'||s==='dark'?s:(d?'dark':'light'))}catch(e){}`;
  return <script dangerouslySetInnerHTML={{ __html: code }} />;
}
