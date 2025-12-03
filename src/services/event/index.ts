import axios from "axios";
import { IEvent } from "@/src/interfaces/event.interface";


export async function getNewestEvent():Promise<IEvent[]> {
    try {
        const {data}= await axios.get(
            `${process.env.NEXT_PUBLIC_BASE_API_URL}/event`
        )
        return data;
    } catch (error) {
        throw error;
    }
}

export async function getAll():Promise<IEvent[]> {
    try {
        const {data}= await axios.get(
            `${process.env.NEXT_PUBLIC_BASE_API_URL}/event`
        )
        return data;
    } catch (error) {
        throw error;
    }
}


export async function getEventBySlug(slug: string): Promise<IEvent[]> {
  try {
        const {data}= await axios.get(
            `${process.env.NEXT_PUBLIC_BASE_API_URL}/event?where=slug%3D'${slug}'`
        )
        return data;
    } catch (error) {
        throw error;
    }
}

export async function createEvent(
    params: Partial<IEvent>
):Promise<IEvent[]> {
 try {
    const { data } = await axios.post(
      `${process.env.NEXT_PUBLIC_BASE_API_URL}/event`,
      {
        ...params,
      }
    );
    return data;
 } catch (error) {
    throw error;
 }   
}