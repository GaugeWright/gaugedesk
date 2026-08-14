/**
 * Opening a Settings room, in one place.
 *
 * The account menu is a door and Settings owns its own navigation, so reaching any
 * setting is two acts: open the menu, then choose the room. Every feature that needs a
 * room went through its own copy of that walk before, which is how a menu change
 * touched a dozen step files at once.
 */
import type { Page } from "@playwright/test";
import { expect } from "@playwright/test";

export type SettingsRoom = "account" | "models" | "devices" | "behaviour";

/** Open the bottom-left account menu. */
export async function openAccountMenu(page: Page): Promise<void> {
    await page.locator("[data-account-menu-trigger]").click();
    await expect(page.locator("[data-account-menu]")).toBeVisible();
}

/** Open Settings and land in `room`. */
export async function openSettings(page: Page, room: SettingsRoom): Promise<void> {
    await openAccountMenu(page);
    await page.locator('[data-account-menu-item="settings"]').click();
    await expect(page.locator("[data-settings-surface]")).toBeVisible();
    await page.locator(`[data-settings-room="${room}"]`).click();
    await expect(page.locator(`[data-settings-room-body="${room}"]`)).toBeVisible();
}

/** Close whichever settings modal is open. */
export async function closeSettings(page: Page): Promise<void> {
    await page.getByRole("button", { name: "close", exact: true }).click();
}
