export namespace content {
	
	export class Entry {
	    name: string;
	    size: number;
	    // Go type: time
	    modified: any;
	    dir?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Entry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.size = source["size"];
	        this.modified = this.convertValues(source["modified"], null);
	        this.dir = source["dir"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Report {
	    type: string;
	    description: string;
	    size: number;
	    archive?: boolean;
	    entries?: Entry[];
	    entryCount?: number;
	    uncompressed?: number;
	    notes?: string[];
	
	    static createFrom(source: any = {}) {
	        return new Report(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.description = source["description"];
	        this.size = source["size"];
	        this.archive = source["archive"];
	        this.entries = this.convertValues(source["entries"], Entry);
	        this.entryCount = source["entryCount"];
	        this.uncompressed = source["uncompressed"];
	        this.notes = source["notes"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace inspect {
	
	export class Legacy {
	    keyBits: number;
	    chunks?: number;
	    chunkSize?: number;
	    truncated?: boolean;
	    key?: string;
	
	    static createFrom(source: any = {}) {
	        return new Legacy(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.keyBits = source["keyBits"];
	        this.chunks = source["chunks"];
	        this.chunkSize = source["chunkSize"];
	        this.truncated = source["truncated"];
	        this.key = source["key"];
	    }
	}
	export class Recipient {
	    type: string;
	    description: string;
	    count: number;
	    keys?: string[];
	    unidentified?: number;
	
	    static createFrom(source: any = {}) {
	        return new Recipient(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.description = source["description"];
	        this.count = source["count"];
	        this.keys = source["keys"];
	        this.unidentified = source["unidentified"];
	    }
	}
	export class Signature {
	    fingerprint: string;
	    name?: string;
	    own?: boolean;
	    known: boolean;
	    // Go type: time
	    signedAt: any;
	
	    static createFrom(source: any = {}) {
	        return new Signature(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.fingerprint = source["fingerprint"];
	        this.name = source["name"];
	        this.own = source["own"];
	        this.known = source["known"];
	        this.signedAt = this.convertValues(source["signedAt"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Sizes {
	    header: number;
	    payload: number;
	    overhead: number;
	    total: number;
	
	    static createFrom(source: any = {}) {
	        return new Sizes(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.header = source["header"];
	        this.payload = source["payload"];
	        this.overhead = source["overhead"];
	        this.total = source["total"];
	    }
	}
	export class Report {
	    path: string;
	    name: string;
	    fileSize: number;
	    kind: string;
	    format: string;
	    armored?: boolean;
	    encryption?: string;
	    recipients?: Recipient[];
	    postQuantum: boolean;
	    access?: string;
	    sizes?: Sizes;
	    legacy?: Legacy;
	    signature?: Signature;
	    signed?: boolean;
	    content?: content.Report;
	    contentsError?: string;
	    warnings?: string[];
	
	    static createFrom(source: any = {}) {
	        return new Report(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.name = source["name"];
	        this.fileSize = source["fileSize"];
	        this.kind = source["kind"];
	        this.format = source["format"];
	        this.armored = source["armored"];
	        this.encryption = source["encryption"];
	        this.recipients = this.convertValues(source["recipients"], Recipient);
	        this.postQuantum = source["postQuantum"];
	        this.access = source["access"];
	        this.sizes = this.convertValues(source["sizes"], Sizes);
	        this.legacy = this.convertValues(source["legacy"], Legacy);
	        this.signature = this.convertValues(source["signature"], Signature);
	        this.signed = source["signed"];
	        this.content = this.convertValues(source["content"], content.Report);
	        this.contentsError = source["contentsError"];
	        this.warnings = source["warnings"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	

}

export namespace main {
	
	export class DecryptRequest {
	    files: string[];
	    outputDir: string;
	    requireSigner: string;
	    overwrite: boolean;
	
	    static createFrom(source: any = {}) {
	        return new DecryptRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.files = source["files"];
	        this.outputDir = source["outputDir"];
	        this.requireSigner = source["requireSigner"];
	        this.overwrite = source["overwrite"];
	    }
	}
	export class EncryptRequest {
	    files: string[];
	    outputDir: string;
	    mode: string;
	    recipients: string[];
	    passphrase: string;
	    sign: boolean;
	    signAs: string;
	    armor: boolean;
	    overwrite: boolean;
	
	    static createFrom(source: any = {}) {
	        return new EncryptRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.files = source["files"];
	        this.outputDir = source["outputDir"];
	        this.mode = source["mode"];
	        this.recipients = source["recipients"];
	        this.passphrase = source["passphrase"];
	        this.sign = source["sign"];
	        this.signAs = source["signAs"];
	        this.armor = source["armor"];
	        this.overwrite = source["overwrite"];
	    }
	}
	export class SignerInfo {
	    name: string;
	    fingerprint: string;
	    known: boolean;
	    own: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SignerInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.fingerprint = source["fingerprint"];
	        this.known = source["known"];
	        this.own = source["own"];
	    }
	}
	export class FileInfo {
	    path: string;
	    name: string;
	    size: number;
	    kind: string;
	    kindLabel: string;
	    recipients: string[];
	    postQuantum: boolean;
	    legacyKeyBits: number;
	    signer?: SignerInfo;
	    signedAt: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new FileInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.name = source["name"];
	        this.size = source["size"];
	        this.kind = source["kind"];
	        this.kindLabel = source["kindLabel"];
	        this.recipients = source["recipients"];
	        this.postQuantum = source["postQuantum"];
	        this.legacyKeyBits = source["legacyKeyBits"];
	        this.signer = this.convertValues(source["signer"], SignerInfo);
	        this.signedAt = source["signedAt"];
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ImportResult {
	    kind: string;
	    name: string;
	    message: string;
	    warning: string;
	
	    static createFrom(source: any = {}) {
	        return new ImportResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.kind = source["kind"];
	        this.name = source["name"];
	        this.message = source["message"];
	        this.warning = source["warning"];
	    }
	}
	export class KeyInfo {
	    name: string;
	    kind: string;
	    default: boolean;
	    postQuantum: boolean;
	    locked: boolean;
	    canSign: boolean;
	    fingerprint: string;
	    recipient: string;
	    created: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new KeyInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.kind = source["kind"];
	        this.default = source["default"];
	        this.postQuantum = source["postQuantum"];
	        this.locked = source["locked"];
	        this.canSign = source["canSign"];
	        this.fingerprint = source["fingerprint"];
	        this.recipient = source["recipient"];
	        this.created = source["created"];
	        this.error = source["error"];
	    }
	}
	export class KeyringState {
	    dir: string;
	    default: string;
	    identities: KeyInfo[];
	    contacts: KeyInfo[];
	    legacy: KeyInfo[];
	
	    static createFrom(source: any = {}) {
	        return new KeyringState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.dir = source["dir"];
	        this.default = source["default"];
	        this.identities = this.convertValues(source["identities"], KeyInfo);
	        this.contacts = this.convertValues(source["contacts"], KeyInfo);
	        this.legacy = this.convertValues(source["legacy"], KeyInfo);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class OpResult {
	    input: string;
	    output: string;
	    ok: boolean;
	    skipped: boolean;
	    error: string;
	    warnings: string[];
	    format: string;
	    signed: boolean;
	    signer?: SignerInfo;
	    signedAt: string;
	
	    static createFrom(source: any = {}) {
	        return new OpResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.input = source["input"];
	        this.output = source["output"];
	        this.ok = source["ok"];
	        this.skipped = source["skipped"];
	        this.error = source["error"];
	        this.warnings = source["warnings"];
	        this.format = source["format"];
	        this.signed = source["signed"];
	        this.signer = this.convertValues(source["signer"], SignerInfo);
	        this.signedAt = source["signedAt"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SignRequest {
	    files: string[];
	    signAs: string;
	    outputDir: string;
	    overwrite: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SignRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.files = source["files"];
	        this.signAs = source["signAs"];
	        this.outputDir = source["outputDir"];
	        this.overwrite = source["overwrite"];
	    }
	}
	
	export class VerifyRequest {
	    sigFile: string;
	    content: string;
	
	    static createFrom(source: any = {}) {
	        return new VerifyRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sigFile = source["sigFile"];
	        this.content = source["content"];
	    }
	}

}

