import { render } from "solid-js/web";
import { GaugeAppsComposition } from "./gaugeapps-lab";

const root = document.getElementById("root");
if (root) render(() => <GaugeAppsComposition />, root);
