import { createHmac } from "crypto";

export class PayloadSigner {
    /**
     * Signs a payload using HMAC-SHA256.
     */
    public static sign(payload: string, secret: string): string {
        return createHmac("sha256", secret).update(payload).digest("hex");
    }

    /**
     * Verifies a payload signature.
     */
    public static verify(payload: string, signature: string, secret: string): boolean {
        const expectedSignature = this.sign(payload, secret);
        return expectedSignature === signature;
    }
}
