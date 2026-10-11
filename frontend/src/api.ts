export async function api<T>(path:string, options?:RequestInit):Promise<T> {
  const response = await fetch('/api'+path,{...options,headers:{'Content-Type':'application/json',...options?.headers}})
  if(!response.ok){const body=await response.json().catch(()=>({}));throw new Error(body.detail || `Request failed (${response.status})`)}
  return response.json()
}
export function download(data:unknown,name:string){const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=name;a.click();URL.revokeObjectURL(url)}
