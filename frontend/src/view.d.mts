export function escapeHTML(value: unknown): string;
export function filterFindings<T extends {group:string;kind:string;confidence:string;location:string;target:string}>(findings:T[],group:string,kind:string,confidence:string,query:string):T[];
export function summarize(findings:{id:string;kind:string;size:number|null}[],selected:Set<string>):{count:number;services:number;measuredBytes:number;unmeasured:number};

export function canExecutePlan(plan: unknown,busy:boolean,now?:number):boolean;
export function operationSummary(operation:unknown):{total:number;quarantined:number;restored:number;failed:number;recovery:number};

export function eligibilityLabel(value: string): string;
