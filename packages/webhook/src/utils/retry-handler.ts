export interface RetryOptions {
    readonly maxRetries: number;
    readonly initialDelayMs: number;
}

export class RetryHandler {
    public static async execute<T>(
        operation: () => Promise<T>,
        options: RetryOptions = { maxRetries: 3, initialDelayMs: 1000 }
    ): Promise<T> {
        let lastError: any;
        let delay = options.initialDelayMs;

        for (let attempt = 0; attempt <= options.maxRetries; attempt++) {
            try {
                return await operation();
            } catch (error) {
                lastError = error;
                if (attempt === options.maxRetries) break;

                await new Promise(resolve => setTimeout(resolve, delay));
                delay *= 2; // Exponential backoff
            }
        }

        throw lastError;
    }
}
