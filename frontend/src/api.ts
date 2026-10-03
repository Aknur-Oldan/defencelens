export async function api<T>(path:string, options:RequestInit={}):Promise<T>{
  const headers:Record<string,string>={Authorization:'Bearer '+(sessionStorage.getItem('lens-token')||'')};
  if(options.body && !(options.body instanceof FormData)) headers['Content-Type']='application/json';
  const response=await fetch('/api'+path,{...options,headers:{...headers,...options.headers}});
  if(!response.ok){
    const body=await response.json().catch(()=>({detail:'Service unavailable'}));
    throw new Error(typeof body.detail==='string'?body.detail:JSON.stringify(body.detail));
  }
  return response.json();
}
export const date=(v:string|null|undefined)=>v?new Date(v).toLocaleString('en-GB'):'No data yet';
export const status:Record<string,string>={open:'Open',investigating:'Investigating',resolved:'Resolved',false_positive:'False positive',pending:'Waiting in queue',queued:'Queued',running:'Scanning',retrying:'Retrying',completed:'Ready',failed:'Error',live:'Receiving data',stale:'No fresh data',never:'Waiting for data',error:'Data error',ok:'Available',unavailable:'Unavailable',operator_confirmed:'Operator confirmed',unverified:'Unverified',pass:'Pass',fail:'Fail'};
