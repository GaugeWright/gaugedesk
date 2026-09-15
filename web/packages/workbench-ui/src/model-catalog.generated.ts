// GaugeDesk-owned model catalog. The `.generated` module name is retained for
// package compatibility; the adjacent JSON contract is the single data source
// consumed by both GaugeDesk and composed server implementations.
import catalog from "./model-catalog.json";

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

export const MODEL_CATALOG: readonly CatalogModel[] = catalog;
