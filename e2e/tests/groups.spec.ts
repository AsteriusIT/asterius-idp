import { expect, test } from '@playwright/test';
import { open, signIn } from '../src/console.js';
import { USERNAME } from '../src/environment.js';

test.beforeEach(() => {
  test.skip(test.info().project.name === 'no-js', 'the administration console requires JavaScript');
});

/** Membership is the switch: the same group assignment appears and disappears
 * from the user's effective-role view without a direct user grant. */
test('group membership changes effective application roles', async ({ page }) => {
  const suffix = Date.now().toString(36);
  const role = `browser-reader-${suffix}`;
  const group = `browser-group-${suffix}`;
  const displayName = `Browser group ${suffix}`;

  await signIn(page);
  await open(page, 'Roles', 'Roles');
  await page.getByRole('button', { name: 'New role' }).click();
  const roleDialog = page.getByRole('dialog');
  await roleDialog.getByLabel('Name').fill(role);
  await roleDialog.getByLabel('Description').fill('Browser membership lifecycle');
  await roleDialog.getByRole('button', { name: 'Create role' }).click();

  await open(page, 'Groups', 'Groups');
  await page.getByRole('button', { name: 'Create group' }).click();
  const groupDialog = page.getByRole('dialog');
  await groupDialog.getByLabel('Machine name').fill(group);
  await groupDialog.getByLabel('Display name').fill(displayName);
  await groupDialog.getByRole('button', { name: 'Save group' }).click();

  await page.getByRole('tab', { name: 'Roles' }).click();
  await page.getByLabel('Role', { exact: true }).selectOption(role);
  await page.getByRole('button', { name: 'Assign role' }).click();
  await expect(page.getByRole('cell', { name: role, exact: true })).toBeVisible();

  await open(page, 'Users', 'Users');
  await page.getByLabel('Search').fill(USERNAME);
  await page.getByRole('button', { name: 'Search' }).click();
  await page.getByRole('button', { name: USERNAME, exact: true }).click();
  await page.getByRole('tab', { name: 'Groups' }).click();
  await page.getByLabel('Find a group').fill(group);
  await page.getByRole('button', { name: 'Search groups' }).click();
  const choice = page.getByRole('radio', { name: new RegExp(`${displayName}.*${group}`) });
  await expect(choice).toBeVisible();
  await choice.check();
  await page.getByRole('button', { name: 'Add to group' }).click();
  const membership = page.getByRole('row', { name: new RegExp(`${displayName}.*${group}`) });
  await expect(membership).toBeVisible();

  await page.getByRole('tab', { name: 'Roles' }).click();
  const inherited = page.getByRole('row', { name: new RegExp(role) });
  await expect(inherited).toContainText(`${displayName} (${group})`);
  await expect(inherited.getByRole('button', { name: /Withdraw/ })).toHaveCount(0);

  await page.getByRole('tab', { name: 'Groups' }).click();
  await membership.getByRole('button', { name: new RegExp(`Remove ${displayName}`) }).click();
  await page.getByRole('tab', { name: 'Roles' }).click();
  await expect(page.getByRole('cell', { name: role, exact: true })).toHaveCount(0);
});
