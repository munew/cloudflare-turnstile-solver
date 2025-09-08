use crate::solver::entries::{get_string_at_offset, FingerprintEntryBase};
use crate::solver::vm_parser::TurnstileTaskEntryContext;
use crate::solver::vm_parser::VMEntryValue;
use anyhow::{Context, Error};
use async_trait::async_trait;
use rand::{rng, Rng};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

#[derive(Debug, Clone)]
pub struct ElementParentChecksEntry {
    key: String,
    value: String,

    query_selector_calls: Vec<String>,
}

#[async_trait]
impl FingerprintEntryBase for ElementParentChecksEntry {
    fn parse(
        quick_idx_map: &FxHashMap<String, usize>,
        strings: &[String],
        _: &[VMEntryValue],
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let key = get_string_at_offset(quick_idx_map, strings, "toString", 1)?;
        let mut elements = Elements::default();

        // find created elements
        let mut is_first = true;
        for (i, s) in strings.iter().enumerate() {
            if s == "id" {
                let id = strings[i + 1].to_string();
                elements.add_element(id.clone(), vec![]);

                if !is_first {
                    elements.get_element_mut_by_id(&id).unwrap().parent = Some(strings[i - 2].to_string());
                }

                is_first = false;
            }

            if s.starts_with("<") && s.ends_with(">") {
                // let r#type = s[1..].split(" ").next().unwrap();

                let id = s
                    .split("id=\"")
                    .nth(1)
                    .unwrap()
                    .split("\" ")
                    .next()
                    .unwrap();

                let classes: Vec<String> = s
                    .split("class=\"")
                    .nth(1)
                    .unwrap()
                    .split("\">")
                    .next()
                    .unwrap()
                    .split(" ")
                    .map(|k| k.to_string())
                    .collect();

                elements.add_element(id.to_string(), classes);

                if !is_first {
                    if &strings[i - 1] == "beforeend" && &strings[i - 2] == "insertAdjacentHTML" {
                        elements.get_element_mut_by_id(&id).unwrap().parent = Some(strings[i - 3].to_string());
                    } else if &strings[i + 1] == "innerHTML" && elements.get_element_mut(&strings[i - 1]).is_some() {
                        elements.get_element_mut_by_id(&id).unwrap().parent = Some(strings[i - 1].to_string());
                    }
                }

                is_first = false;
            }
        }

        // add classes
        for (i, s) in strings.iter().enumerate() {
            if s != "className" {
                continue;
            }

            let prev_string = &strings[i - 1];
            if let Some(prev_string) = prev_string.strip_prefix(" ") {
                let query = &strings[i - 2];
                if let Some(element) = elements.get_element_mut(query) {
                    element.classes.push(prev_string.to_string());
                } else {
                    println!("classes step: could not find element {query}");
                }
            }
        }

        // find titles
        for (i, s) in strings.iter().enumerate() {
            if s == "title" {
                let query = &strings[i - 1];
                let title = &strings[i + 1];

                if *title == key {
                    continue;
                }

                if let Some(element) = elements.get_element_mut(query) {
                    element.title = Some(title.to_string());
                } else {
                    println!("Could not find element {query}");
                }
            }
        }

        // now we game
        let mut query_selector_calls = Vec::new();
        for s in strings {
            if (s.starts_with("#") || s.starts_with(".")) && !s.contains(" ") && !s.contains("{") && !s.contains(":") {
                query_selector_calls.push(s.to_string());
            }
        }


        let mut value = String::new();
        for (i, s) in strings.iter().enumerate() {
            if s != "title" || strings[i + 1] != key {
                continue;
            }

            let first_element = &strings[i - 2];
            let second_element = &strings[i - 1];

            let result = elements.find_parent_containing(first_element, second_element).context("could not find parent containing. giving up.")?;
            let title = result.title.context("could not find result title. giving up.")?;
            value.push_str(&title);
        }

        Ok(Self {
            query_selector_calls,
            key,
            value,
        })
    }


    async fn write_entry(
        &self,
        task: &mut TurnstileTaskEntryContext,
        map: &mut Map<String, Value>,
    ) -> Result<usize, Error> {
        task.query_selector_calls.extend(self.query_selector_calls.clone());
        map.insert(self.key.clone(), self.value.clone().into());
        Ok(rng().random_range(3..=6))
    }
}

#[derive(Debug, Clone)]
struct Element {
    parent: Option<String>,
    id: String,
    classes: Vec<String>,
    title: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct Elements {
    elements: Vec<Element>,
}

impl Elements {
    fn add_element(&mut self, id: String, classes: Vec<String>) {
        self.elements.push(Element {
            parent: None,
            id,
            classes,
            title: None,
        });
    }

    fn get_element_mut_by_id(&mut self, id: &str) -> Option<&mut Element> {
        self.elements.iter_mut().find(|element| element.id == id)
    }

    fn get_element_mut_by_class(&mut self, class: &str) -> Option<&mut Element> {
        self.elements
            .iter_mut()
            .find(|element| element.classes.contains(&class.to_string()))
    }

    fn get_element_by_id(&self, id: &str) -> Option<&Element> {
        self.elements.iter().find(|element| element.id == id)
    }

    fn get_element_by_class(&self, class: &str) -> Option<&Element> {
        self.elements
            .iter()
            .find(|element| element.classes.contains(&class.to_string()))
    }


    fn get_element(&self, query: &str) -> Option<&Element> {
        if let Some(stripped) = query.strip_prefix(".") {
            return self.get_element_by_class(stripped);
        } else if let Some(stripped) = query.strip_prefix("#") {
            return self.get_element_by_id(stripped);
        }

        None
    }

    fn get_element_mut(&mut self, query: &str) -> Option<&mut Element> {
        if let Some(stripped) = query.strip_prefix(".") {
            return self.get_element_mut_by_class(stripped);
        } else if let Some(stripped) = query.strip_prefix("#") {
            return self.get_element_mut_by_id(stripped);
        }

        None
    }

    fn find_parent_containing(&self, element1_query: &str, element2_query: &str) -> Option<Element> {
        let element1 = self.get_element(element1_query)?;
        let element2 = self.get_element(element2_query)?;
        if element1.id == element2.id {
            return Some(element1.clone());
        }

        if self.does_contain(element1, element2) {
            return Some(element1.clone());
        }

        if self.does_contain(element2, element1) {
            return Some(element2.clone());
        }

        let mut current = element1;
        while let Some(parent_selector) = &current.parent {
            let parent = if let Some(id) = parent_selector.strip_prefix("#") {
                self.elements.iter().find(|e| e.id == id)
            } else if let Some(class) = parent_selector.strip_prefix(".") {
                self.elements.iter().find(|e| e.classes.contains(&class.to_string()))
            } else {
                self.elements.iter().find(|e| e.id == *parent_selector)
            };

            if let Some(parent_element) = parent {
                if parent_element.id == element2.id || self.does_contain(parent_element, element2) {
                    return Some(parent_element.clone());
                }
                current = parent_element;
            } else {
                break;
            }
        }

        None
    }

    fn does_contain(&self, container: &Element, target: &Element) -> bool {
        let container_id_selector = format!("#{}", container.id);
        let container_class_selectors: Vec<String> = container.classes.iter()
            .map(|class| format!(".{class}"))
            .collect();

        if let Some(parent_ref) = &target.parent && (parent_ref == &container_id_selector || container_class_selectors.contains(parent_ref)) {
            return true;
        }

        let children = self.get_children(container);
        for child in children {
            if child.id == target.id || self.does_contain(&child, target) {
                return true;
            }
        }

        false
    }

    fn get_children(&self, element: &Element) -> Vec<Element> {
        let id_selector = format!("#{}", element.id);
        let class_selectors: Vec<String> = element.classes.iter()
            .map(|class| format!(".{class}"))
            .collect();

        self.elements.iter()
            .filter(|e| {
                e.parent.as_ref().is_some_and(|parent_ref| {
                    parent_ref == &id_selector || class_selectors.contains(parent_ref)
                })
            })
            .cloned()
            .collect()
    }
}
