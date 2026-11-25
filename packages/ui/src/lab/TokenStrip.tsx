"use client";

import {CellSwitch, NumberValue} from "@heroui-pro/react";
import {KPI} from "@heroui-pro/react/kpi";
import {useAppFormat} from "@ctrlz/i18n/format.ts";
import {reactAriaLocale} from "@ctrlz/i18n/locale.ts";
import {Avatar, Checkbox, Switch} from "@heroui/react";
import {useTranslations} from "next-intl";

import {sparkline} from "./fixtures.ts";
import {SectionTitle} from "./SectionTitle.tsx";

// A small strip of the things lab.spec.ts measures that no other lab page holds (spec 5.3 and 6.3):
// the chart palette on a real sparkline, every size and state of a switch, a cell switch, the avatar and
// checkbox that D47 leaves on the 0.4 rule, and the two tile squares whose radius comes from
// radius.table.ts. The token-lab (TokenLab.tsx, spec 6.3) holds the full set of radius rows and
// radius.spec.ts measures them; these few stay for lab.spec.ts, which also reads the chart colours and the off switch.

const SIZES = ["sm", "md", "lg"] as const;
const STATES: {key: "off" | "on" | "offDisabled" | "onDisabled"; selected: boolean; disabled: boolean}[] = [
  {key: "off", selected: false, disabled: false},
  {key: "on", selected: true, disabled: false},
  {key: "offDisabled", selected: false, disabled: true},
  {key: "onDisabled", selected: true, disabled: true},
];

export function TokenStrip() {
  const t = useTranslations("lab.tokens");
  // Passed to NumberValue explicitly, so the digits do not depend on where the I18nProvider sits (measured: with
  // the prop dropped the app's provider still gives fa its digits today). lab.spec.ts checks the printed text.
  const {locale} = useAppFormat();

  return (
    <section aria-labelledby="token-strip" className="flex flex-col gap-3">
      <SectionTitle id="token-strip" title={t("title")} />
      <div className="flex flex-wrap items-start gap-4">
        <div className="w-48">
          <KPI>
            <KPI.Header>
              <KPI.Title role="term">{t("kpi")}</KPI.Title>
            </KPI.Header>
            <KPI.Content>
              <NumberValue className="kpi__value" locale={reactAriaLocale[locale]} maximumFractionDigits={0} value={128450} />
            </KPI.Content>
            {/* The same sparkline as the product's KPI card: no area fill, the accent as chart-3. */}
            <KPI.Chart
              className="pb-3 [--kpi-chart-fade:18%]"
              areaProps={{fill: "none"}}
              color="var(--chart-3)"
              data={sparkline.map((value, i) => ({i, value}))}
              height={40}
              strokeWidth={1.5}
            />
          </KPI>
        </div>
        {/* Every switch size in the four states a reader meets. D47: the track and the thumb are pills. */}
        <div className="flex flex-col gap-3 rounded-(--radius-box) bg-surface p-4 shadow-surface" data-shapes="switch">
          {SIZES.map((size) => (
            <div key={size} className="flex items-center gap-4">
              {STATES.map(({key, selected, disabled}) => (
                <Switch
                  key={key}
                  aria-label={t("switchLabel", {size: t(`sizes.${size}`), state: t(`states.${key}`)})}
                  defaultSelected={selected}
                  isDisabled={disabled}
                  size={size}
                >
                  <Switch.Content>
                    <Switch.Control>
                      <Switch.Thumb />
                    </Switch.Control>
                  </Switch.Content>
                </Switch>
              ))}
            </div>
          ))}
        </div>
        {/* CellSwitch renders the stock Switch inside, so it must follow the same pill rule. */}
        <div className="w-60 rounded-(--radius-box) bg-surface p-4 shadow-surface" data-shapes="cell-switch">
          <CellSwitch defaultSelected aria-label={t("cellSwitchLabel")}>
            <CellSwitch.Trigger>
              <CellSwitch.Label>{t("cellSwitchLabel")}</CellSwitch.Label>
              <CellSwitch.Control />
            </CellSwitch.Trigger>
          </CellSwitch>
        </div>
        {/* Avatars and the checkbox keep the 0.4 rule of D16 (D47 leaves them alone). */}
        <div className="flex flex-col gap-3 rounded-(--radius-box) bg-surface p-4 shadow-surface" data-shapes="avatar-checkbox">
          <div className="flex items-center gap-3">
            {SIZES.map((size) => (
              <Avatar key={size} aria-label={t("avatar", {size: t(`sizes.${size}`)})} size={size}>
                <Avatar.Fallback>{t("avatarInitial")}</Avatar.Fallback>
              </Avatar>
            ))}
          </div>
          <div className="flex items-center gap-4">
            {(["off", "on"] as const).map((key) => (
              <Checkbox key={key} aria-label={t("checkbox", {state: t(`checkboxStates.${key}`)})} defaultSelected={key === "on"}>
                <Checkbox.Content>
                  <Checkbox.Control>
                    <Checkbox.Indicator />
                  </Checkbox.Control>
                </Checkbox.Content>
              </Checkbox>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-3 rounded-(--radius-box) bg-surface p-4 shadow-surface">
          {/* tile-11 and tile-6 take their radius from radius.table.ts. */}
          <span aria-hidden className="tile-11 grid size-11 place-items-center bg-default" />
          <span aria-hidden className="tile-6 grid size-6 place-items-center bg-accent text-accent-foreground" />
        </div>
      </div>
    </section>
  );
}
