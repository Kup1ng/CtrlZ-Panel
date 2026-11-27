"use client";

import {ComboBox, Input, Label, ListBox} from "@heroui/react";
import {useClients} from "@ctrlz/api-client/hooks/clients.ts";
import {useTranslations} from "next-intl";
import {useDeferredValue, useMemo, useState} from "react";

import {Tech} from "../data/Tech.tsx";

// The client picker of the Resolvers dialog and of the Apple builder: the values of a client carry its label (`<resolver>-<client>.<zone>`,
// SC 3.2), so a device that should show up as its own client in the logs is set up with the client's own view. The search goes to the API
// (`q`), because an Endpoint may have a thousand of them; the first page of the answer is the list. "" is the Endpoint itself.
//
// The chosen client stays in the list while the search shows others, otherwise the field would go blank the moment a person types.

const SELF = "__self";
type Option = {id: string; name: string; label?: string};

export function ClientPicker({
  endpointId,
  value,
  onChange,
  label,
  className,
  isDisabled,
}: {
  endpointId: string;
  /** The client label, or "" for the Endpoint itself. */
  value: string;
  onChange: (label: string) => void;
  label: string;
  className?: string;
  isDisabled?: boolean;
}) {
  const t = useTranslations("setup");
  const [query, setQuery] = useState("");
  const [chosen, setChosen] = useState<Option | null>(null);
  // The field shows the name of what is chosen, and reports it as typed text: that is not a search.
  // A client chosen elsewhere (Resolvers hands it to this picker, and to the Apple builder) may be neither chosen here nor on the first page: it still
  // needs an option, or the field would show nothing while the title and every value carry that client (S7-r3-3). Its label stands for its name then.
  const current = useMemo<Option | null>(() => (value === "" ? null : chosen?.id === value ? chosen : {id: value, name: value, label: value}), [value, chosen]);
  const shownName = current ? current.name : t("client.self");
  const typed = query.trim();
  const q = useDeferredValue(typed === shownName ? "" : typed);
  const {clients, isPending} = useClients(endpointId, q ? {q} : {});

  const options = useMemo<Option[]>(() => {
    const list: Option[] = [{id: SELF, name: t("client.self")}];
    for (const c of clients) {
      // The `default` label is the Endpoint's own, already the first line.
      if (c.label === "default") continue;
      list.push({id: c.label, name: c.alias ? `${c.alias} (${c.label})` : c.label, label: c.label});
    }
    if (current && !list.some((o) => o.id === current.id)) list.push(current);
    return list;
  }, [clients, current, t]);

  return (
    <ComboBox
      className={className}
      isDisabled={isDisabled}
      variant="secondary"
      fullWidth
      items={options}
      selectedKey={value === "" ? SELF : value}
      onSelectionChange={(key) => {
        if (key === null) return;
        const option = options.find((o) => o.id === key);
        setChosen(option ?? null);
        setQuery("");
        onChange(key === SELF ? "" : String(key));
      }}
      onInputChange={setQuery}
      menuTrigger="focus"
      allowsEmptyCollection
    >
      <Label>{label}</Label>
      <ComboBox.InputGroup>
        <Input placeholder={t("client.search")} />
        <ComboBox.Trigger />
      </ComboBox.InputGroup>
      <ComboBox.Popover>
        <ListBox
          renderEmptyState={() => <span className="text-muted p-2 text-sm">{isPending ? t("client.loading") : t("client.none")}</span>}
        >
          {(item: Option) => (
            <ListBox.Item id={item.id} textValue={item.name}>
              {item.label ? <Tech>{item.name}</Tech> : item.name}
              <ListBox.ItemIndicator />
            </ListBox.Item>
          )}
        </ListBox>
      </ComboBox.Popover>
    </ComboBox>
  );
}
