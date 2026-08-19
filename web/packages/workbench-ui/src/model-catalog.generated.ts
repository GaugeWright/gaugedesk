// GaugeDesk-owned model catalog snapshot. The `.generated` filename is retained
// for package compatibility; Pi is no longer its authority or update source.

/** A model GaugeDesk may bind through WhippleScript, with picker metadata. */
export interface CatalogModel {
    readonly provider: string;
    readonly id: string;
    readonly name: string;
    readonly reasoning: boolean;
    /** Supported reasoning levels (off | minimal | low | medium | high | xhigh). */
    readonly thinking: readonly string[];
    /** Input modalities the model accepts (e.g. "text", "image"). */
    readonly input: readonly string[];
}

export const MODEL_CATALOG: readonly CatalogModel[] = [
    {
        "provider": "anthropic",
        "id": "claude-3-haiku-20240307",
        "name": "Claude Haiku 3",
        "reasoning": false,
        "thinking": [
            "off"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-3-5-haiku-20241022",
        "name": "Claude Haiku 3.5",
        "reasoning": false,
        "thinking": [
            "off"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-3-5-haiku-latest",
        "name": "Claude Haiku 3.5 (latest)",
        "reasoning": false,
        "thinking": [
            "off"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-haiku-4-5-20251001",
        "name": "Claude Haiku 4.5",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-haiku-4-5",
        "name": "Claude Haiku 4.5 (latest)",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-3-opus-20240229",
        "name": "Claude Opus 3",
        "reasoning": false,
        "thinking": [
            "off"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-opus-4-20250514",
        "name": "Claude Opus 4",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-opus-4-0",
        "name": "Claude Opus 4 (latest)",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-opus-4-1-20250805",
        "name": "Claude Opus 4.1",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-opus-4-1",
        "name": "Claude Opus 4.1 (latest)",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-opus-4-5-20251101",
        "name": "Claude Opus 4.5",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-opus-4-5",
        "name": "Claude Opus 4.5 (latest)",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-opus-4-6",
        "name": "Claude Opus 4.6",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-opus-4-7",
        "name": "Claude Opus 4.7",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-3-sonnet-20240229",
        "name": "Claude Sonnet 3",
        "reasoning": false,
        "thinking": [
            "off"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-3-5-sonnet-20240620",
        "name": "Claude Sonnet 3.5",
        "reasoning": false,
        "thinking": [
            "off"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-3-5-sonnet-20241022",
        "name": "Claude Sonnet 3.5 v2",
        "reasoning": false,
        "thinking": [
            "off"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-3-7-sonnet-20250219",
        "name": "Claude Sonnet 3.7",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-sonnet-4-20250514",
        "name": "Claude Sonnet 4",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-sonnet-4-0",
        "name": "Claude Sonnet 4 (latest)",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-sonnet-4-5-20250929",
        "name": "Claude Sonnet 4.5",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-sonnet-4-5",
        "name": "Claude Sonnet 4.5 (latest)",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "anthropic",
        "id": "claude-sonnet-4-6",
        "name": "Claude Sonnet 4.6",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "openai",
        "id": "gpt-5.4",
        "name": "GPT-5.4",
        "reasoning": true,
        "thinking": [
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "openai",
        "id": "gpt-5.4-mini",
        "name": "GPT-5.4 mini",
        "reasoning": true,
        "thinking": [
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "openai",
        "id": "gpt-5.4-nano",
        "name": "GPT-5.4 nano",
        "reasoning": true,
        "thinking": [
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "openai",
        "id": "gpt-5.4-pro",
        "name": "GPT-5.4 Pro",
        "reasoning": true,
        "thinking": [
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "openai",
        "id": "gpt-5.5",
        "name": "GPT-5.5",
        "reasoning": true,
        "thinking": [
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "openai",
        "id": "gpt-5.5-pro",
        "name": "GPT-5.5 Pro",
        "reasoning": true,
        "thinking": [
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "openai",
        "id": "gpt-5.6-sol",
        "name": "GPT-5.6 Sol",
        "reasoning": true,
        "thinking": [
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "openai",
        "id": "gpt-5.6-terra",
        "name": "GPT-5.6 Terra",
        "reasoning": true,
        "thinking": [
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "openai",
        "id": "gpt-5.6-luna",
        "name": "GPT-5.6 Luna",
        "reasoning": true,
        "thinking": [
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "openai-codex",
        "id": "gpt-5.4",
        "name": "GPT-5.4",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "openai-codex",
        "id": "gpt-5.4-mini",
        "name": "GPT-5.4 Mini",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "openai-codex",
        "id": "gpt-5.5",
        "name": "GPT-5.5",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "openai-codex",
        "id": "gpt-5.6-sol",
        "name": "GPT-5.6 Sol",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "openai-codex",
        "id": "gpt-5.6-terra",
        "name": "GPT-5.6 Terra",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "openai-codex",
        "id": "gpt-5.6-luna",
        "name": "GPT-5.6 Luna",
        "reasoning": true,
        "thinking": [
            "off",
            "minimal",
            "low",
            "medium",
            "high",
            "xhigh"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "xai",
        "id": "grok-4.6",
        "name": "Grok 4.6",
        "reasoning": true,
        "thinking": [
            "off"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "xai",
        "id": "grok-4.5",
        "name": "Grok 4.5",
        "reasoning": true,
        "thinking": [
            "off"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "xai",
        "id": "grok-4.3",
        "name": "Grok 4.3",
        "reasoning": true,
        "thinking": [
            "off"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "xai",
        "id": "grok-4.20",
        "name": "Grok 4.20",
        "reasoning": true,
        "thinking": [
            "off"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "xai",
        "id": "grok-4.20-non-reasoning",
        "name": "Grok 4.20 Non-reasoning",
        "reasoning": false,
        "thinking": [
            "off"
        ],
        "input": [
            "text",
            "image"
        ]
    },
    {
        "provider": "xai",
        "id": "grok-build-0.1",
        "name": "Grok Build 0.1",
        "reasoning": true,
        "thinking": [
            "off"
        ],
        "input": [
            "text",
            "image"
        ]
    }
];
