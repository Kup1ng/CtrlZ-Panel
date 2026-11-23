"use client";

import {Button, Dropdown, Label} from "@heroui/react";
import {Command} from "@heroui-pro/react";
import {normalizeFaSearch} from "@ctrlz/i18n/digits.ts";
import {Icon} from "@ctrlz/icons/Icon.tsx";
import {useTranslations} from "next-intl";
import {useState} from "react";

// T-123, spec 8.4. Sits in PageHeader's `leading` slot on profile pages: a
// Dropdown of {id, name}, and above 10 entries a Command to jump by typing. P1 has
// no profile list, so nothing renders it yet; P2 mounts it with real data. It is
// exercised with fixtures.

export type ProfileOption = {id: string; name: string};

const JUMP_THRESHOLD = 10;
const fold = (s: string) => normalizeFaSearch(s).toLocaleLowerCase();

export function ProfileSwitcher({
  profiles,
  value,
  onChange,
}: {
  profiles: ProfileOption[];
  value: string;
  onChange: (id: string) => void;
}) {
  const t = useTranslations("shell");
  const [jumpOpen, setJumpOpen] = useState(false);
  const current = profiles.find((p) => p.id === value);
  const label = current?.name ?? t("profileSwitcher.none");

  const trigger = (
    <Button variant="outline" aria-label={t("profileSwitcher.label")} onPress={profiles.length > JUMP_THRESHOLD ? () => setJumpOpen(true) : undefined}>
      <span className="max-w-40 truncate">{label}</span>
      <Icon name="chevron" className="size-4 rotate-90" />
    </Button>
  );

  if (profiles.length > JUMP_THRESHOLD) {
    return (
      <>
        {trigger}
        <Command>
          <Command.Backdrop isOpen={jumpOpen} onOpenChange={setJumpOpen}>
            <Command.Container size="md">
              <Command.Dialog aria-label={t("profileSwitcher.label")} filter={(text, input) => fold(text).includes(fold(input))}>
                <Command.InputGroup>
                  <Command.InputGroup.Prefix>
                    <Icon name="search" className="size-4" />
                  </Command.InputGroup.Prefix>
                  <Command.InputGroup.Input placeholder={t("profileSwitcher.search")} />
                </Command.InputGroup>
                <Command.List>
                  {profiles.map((p) => (
                    <Command.Item
                      key={p.id}
                      id={p.id}
                      textValue={p.name}
                      onAction={() => {
                        setJumpOpen(false);
                        onChange(p.id);
                      }}
                    >
                      <span>{p.name}</span>
                    </Command.Item>
                  ))}
                </Command.List>
              </Command.Dialog>
            </Command.Container>
          </Command.Backdrop>
        </Command>
      </>
    );
  }

  return (
    <Dropdown>
      {trigger}
      <Dropdown.Popover placement="bottom start">
        <Dropdown.Menu
          aria-label={t("profileSwitcher.label")}
          selectionMode="single"
          selectedKeys={[value]}
          onSelectionChange={(keys) => {
            const next = [...keys][0];
            if (typeof next === "string" && next !== value) onChange(next);
          }}
        >
          {profiles.map((p) => (
            <Dropdown.Item key={p.id} id={p.id} textValue={p.name}>
              <Label>{p.name}</Label>
              <Dropdown.ItemIndicator />
            </Dropdown.Item>
          ))}
        </Dropdown.Menu>
      </Dropdown.Popover>
    </Dropdown>
  );
}
